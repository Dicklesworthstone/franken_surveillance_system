#![forbid(unsafe_code)]
//! Canonical closed metadata for started and verified local deliveries.

use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor, PrincipalId, TimestampNs,
};

const DOMAIN: &str = "fss.review_delivery_record.v1";
const PROFILE: &str =
    "local-private-file-readback-v1;no-remote-delivery;no-copy-recall;no-read-authority";

/// Maximum canonical delivery metadata, independent of the media byte ceiling.
pub const MAX_DELIVERY_RECORD_BYTES: usize = 16 * 1024;
/// This local readback profile shares the retained review's fixed media ceiling.
const MAX_DELIVERY_MEDIA_BYTES: u64 = 64 * 1024 * 1024;

/// Bounded canonical record failure. Parsing a record never establishes delivery authority.
#[derive(Debug)]
pub enum ReviewDeliveryRecordError {
    /// A canonical primitive or identifier was invalid.
    Contract(ContractError),
    /// The record exceeded this profile's fixed metadata bound.
    Limit,
    /// The identity, integrity, profile or temporal invariants failed.
    Invalid,
}

impl fmt::Display for ReviewDeliveryRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "delivery record contract: {error}"),
            Self::Limit => write!(f, "delivery record exceeds its metadata bound"),
            Self::Invalid => write!(f, "delivery record identity or custody mismatch"),
        }
    }
}
impl std::error::Error for ReviewDeliveryRecordError {}
impl From<ContractError> for ReviewDeliveryRecordError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

/// Durable local operation state. Started includes every not-yet-reconciled outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewDeliveryState {
    /// An attempt was committed, but complete file custody is not yet proven.
    Started,
    /// The exact held local file was read back and its length and digest matched.
    Verified,
}

/// Held-file identity retained after actual readback. No path or private pixels are stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewDeliveryFileIdentity {
    /// Unix device identity of the held file.
    pub device: u64,
    /// Unix inode identity of the held file.
    pub inode: u64,
}

/// Closed, canonical local delivery evidence. Its checksum alone never grants authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewDeliveryRecord {
    pub(super) identity: ContentDigest,
    pub(super) site: String,
    pub(super) recipient: PrincipalId,
    pub(super) review_root: ContentDigest,
    pub(super) review_record: ContentDigest,
    pub(super) media_digest: ContentDigest,
    pub(super) media_bytes: u64,
    pub(super) destination: ContentDigest,
    pub(super) reader_authority: ContentDigest,
    pub(super) started_at: CaptureInterval,
    pub(super) basis: LedgerAnchor,
    pub(super) completion: Option<Completion>,
    pub(super) wire: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Completion {
    pub(super) started_record: ContentDigest,
    pub(super) now: CaptureInterval,
    pub(super) file: ReviewDeliveryFileIdentity,
    pub(super) modified: (i64, u32),
    pub(super) changed: (i64, u32),
}

fn valid_digest(d: ContentDigest) -> bool {
    d.algorithm() == DigestAlgorithm::Sha256 && !d.is_laboratory() && d.bytes() != [0; 32]
}

pub(super) fn delivery_identity(
    site: &str,
    recipient: &PrincipalId,
    root: ContentDigest,
    record: ContentDigest,
    media: ContentDigest,
    bytes: u64,
    destination: ContentDigest,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.review_delivery_identity.v1");
    e.text(site);
    e.text(recipient.as_str());
    e.digest(root);
    e.digest(record);
    e.digest(media);
    e.u64(bytes);
    e.digest(destination);
    ContentDigest::sha256(&e.finish())
}

impl ReviewDeliveryRecord {
    /// Stable operation identity, independent of retries' current-time assertions.
    pub fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Existing retained review graph; this identity is not a read capability.
    pub fn review_root(&self) -> ContentDigest {
        self.review_root
    }
    /// Exact retained review custody record.
    pub fn review_record_digest(&self) -> ContentDigest {
        self.review_record
    }
    /// Digest independently checked against the file on every completion/reconciliation.
    pub fn media_digest(&self) -> ContentDigest {
        self.media_digest
    }
    /// Exact complete file length, including the container.
    pub fn media_bytes(&self) -> u64 {
        self.media_bytes
    }
    /// Exact local recipient. The local caller supplies authentication outside this profile.
    pub fn recipient(&self) -> &PrincipalId {
        &self.recipient
    }
    /// Protected destination binding supplied by the local output owner.
    pub fn destination_binding(&self) -> ContentDigest {
        self.destination
    }
    /// Durable progress, distinct from current file existence or current read authority.
    pub fn state(&self) -> ReviewDeliveryState {
        if self.completion.is_some() {
            ReviewDeliveryState::Verified
        } else {
            ReviewDeliveryState::Started
        }
    }
    /// Explicit time assertion used to admit the first attempt.
    pub fn started_at(&self) -> CaptureInterval {
        self.started_at
    }
    /// Explicit time assertion used for the retained verification, when present.
    pub fn verified_at(&self) -> Option<CaptureInterval> {
        self.completion.as_ref().map(|c| c.now)
    }
    /// Exact inode checked by the retained verification, when present.
    pub fn verified_file(&self) -> Option<ReviewDeliveryFileIdentity> {
        self.completion.as_ref().map(|c| c.file)
    }
    /// Canonical delivery record digest; not proof of the corresponding ledger transition.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.wire)
    }
    /// Complete metadata bytes. No source or derivative media is embedded.
    pub fn to_bytes(&self) -> &[u8] {
        &self.wire
    }

    fn validate(&self) -> Result<(), ReviewDeliveryRecordError> {
        if self.site.is_empty()
            || self.site.len() > 256
            || self.site.chars().any(char::is_control)
            || self.basis.site_lineage != self.site
            || ![
                self.identity,
                self.review_root,
                self.review_record,
                self.media_digest,
                self.destination,
                self.reader_authority,
                self.basis.state_root,
            ]
            .into_iter()
            .all(valid_digest)
            || self.media_bytes == 0
            || self.media_bytes > MAX_DELIVERY_MEDIA_BYTES
            || self.started_at.earliest > self.started_at.latest
        {
            return Err(ReviewDeliveryRecordError::Invalid);
        }
        if let Some(c) = &self.completion {
            if !valid_digest(c.started_record)
                || c.modified.1 >= 1_000_000_000
                || c.changed.1 >= 1_000_000_000
                || c.now.earliest > c.now.latest
                || c.now.earliest < self.started_at.earliest
                || c.now.latest < self.started_at.latest
            {
                return Err(ReviewDeliveryRecordError::Invalid);
            }
        }
        if delivery_identity(
            &self.site,
            &self.recipient,
            self.review_root,
            self.review_record,
            self.media_digest,
            self.media_bytes,
            self.destination,
        ) != self.identity
        {
            return Err(ReviewDeliveryRecordError::Invalid);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, ReviewDeliveryRecordError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.u32(1);
        e.text(PROFILE);
        e.digest(self.identity);
        e.text(&self.site);
        e.text(self.recipient.as_str());
        e.digest(self.review_root);
        e.digest(self.review_record);
        e.digest(self.media_digest);
        e.u64(self.media_bytes);
        e.digest(self.destination);
        e.digest(self.reader_authority);
        e.i128(self.started_at.earliest.0);
        e.i128(self.started_at.latest.0);
        self.basis.encode_canonical(&mut e);
        match &self.completion {
            None => e.u8(1),
            Some(c) => {
                e.u8(2);
                e.digest(c.started_record);
                e.i128(c.now.earliest.0);
                e.i128(c.now.latest.0);
                e.u64(c.file.device);
                e.u64(c.file.inode);
                e.i128(i128::from(c.modified.0));
                e.u32(c.modified.1);
                e.i128(i128::from(c.changed.0));
                e.u32(c.changed.1);
            }
        }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_DELIVERY_RECORD_BYTES {
            return Err(ReviewDeliveryRecordError::Limit);
        }
        Ok(bytes)
    }

    pub(super) fn seal(&mut self) -> Result<(), ReviewDeliveryRecordError> {
        self.wire = self.encode()?;
        Ok(())
    }

    /// Strict metadata decoder with independent digest, full-consumption and canonical checks.
    /// This produces a record value only; guarded ledger inspection is required to trust it.
    pub fn from_bytes(
        bytes: &[u8],
        expected: ContentDigest,
    ) -> Result<Self, ReviewDeliveryRecordError> {
        if bytes.len() > MAX_DELIVERY_RECORD_BYTES
            || !valid_digest(expected)
            || ContentDigest::sha256(bytes) != expected
        {
            return Err(ReviewDeliveryRecordError::Invalid);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != DOMAIN || d.u32()? != 1 || d.text()? != PROFILE {
            return Err(ReviewDeliveryRecordError::Invalid);
        }
        let mut record = Self {
            identity: d.digest()?,
            site: d.text()?.into(),
            recipient: PrincipalId::parse(d.text()?)?,
            review_root: d.digest()?,
            review_record: d.digest()?,
            media_digest: d.digest()?,
            media_bytes: d.u64()?,
            destination: d.digest()?,
            reader_authority: d.digest()?,
            started_at: CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?,
            basis: LedgerAnchor::decode_canonical(&mut d)?,
            completion: None,
            wire: bytes.to_vec(),
        };
        record.completion = match d.u8()? {
            1 => None,
            2 => Some(Completion {
                started_record: d.digest()?,
                now: CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?,
                file: ReviewDeliveryFileIdentity {
                    device: d.u64()?,
                    inode: d.u64()?,
                },
                modified: (
                    i64::try_from(d.i128()?).map_err(|_| ReviewDeliveryRecordError::Invalid)?,
                    d.u32()?,
                ),
                changed: (
                    i64::try_from(d.i128()?).map_err(|_| ReviewDeliveryRecordError::Invalid)?,
                    d.u32()?,
                ),
            }),
            _ => return Err(ReviewDeliveryRecordError::Invalid),
        };
        d.ensure_finished()?;
        if record.encode()? != bytes {
            return Err(ReviewDeliveryRecordError::Invalid);
        }
        Ok(record)
    }
}
