#![forbid(unsafe_code)]
//! Standalone verification of one independently pinned remote object. A successful
//! upload or HEAD is not used as a substitute for reading and hashing its bytes.
//! No source bytes escape this owner; the only output is a bounded receipt.
//! This does not verify an upload journal, part inventory or historical custody origin.

use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContextAuthority, DigestAlgorithm, RegionKind, RegionState, RegionTree,
    RuntimeGrant, Sha256Hasher, TimestampNs,
};
use fss_runtime::authority::AuthorityCx;
use fss_runtime::grant::GrantSet;

use super::http::Boundary;
use super::{S3Credentials, S3Endpoint, S3Error, S3Limits, http, signing};

/// Maximum object size for this bounded native verification profile.
pub const MAX_VERIFIED_OBJECT_BYTES: u64 = 64 * 1024 * 1024;
/// Bound on a canonical receipt; it contains no media, credentials or object key.
pub const MAX_VERIFICATION_RECEIPT_BYTES: usize = 64 * 1024;
const DOMAIN: &str = "fss.s3_object_verification.v1";
const RECEIPT_RESERVATION: u64 = MAX_VERIFICATION_RECEIPT_BYTES as u64;
const GRANTS: [RuntimeGrant; 3] = [
    RuntimeGrant::AdapterNet,
    RuntimeGrant::AdapterAuth,
    RuntimeGrant::ReadMedia,
];

/// Independently obtained source identity, never inferred from an ETag or HEAD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct S3ObjectPin {
    /// SHA-256 of the entire original object.
    pub digest: ContentDigest,
    /// Exact original object length, including zero for the empty object.
    pub bytes: u64,
}
impl S3ObjectPin {
    fn validate(self) -> Result<(), S3Error> {
        if self.digest.algorithm() != DigestAlgorithm::Sha256
            || self.digest.bytes() == [0; 32]
            || self.bytes > MAX_VERIFIED_OBJECT_BYTES
            || (self.bytes == 0 && self.digest != ContentDigest::sha256(b""))
        {
            return Err(S3Error::Configuration);
        }
        Ok(())
    }
}

/// A clock boundary receives the real read authority, not synthesized upload
/// authority. Its result is rechecked for regression, deadline and cancellation.
pub trait S3ReadClock {
    /// Read the caller's clock under the current object-read owner.
    fn now(&mut self, authority: &AuthorityCx) -> Result<TimestampNs, S3Error>;
}

/// Caller-owned, fresh ObjectStore region. Its only grants must be scoped
/// network, authentication and raw-media reads. The caller drains this region
/// after success or refusal; no durable upload owner is resumed or modified.
pub struct S3ReadIo<'a> {
    /// Actual execution authority; its finite allowance is spent before I/O.
    pub authority: &'a mut AuthorityCx,
    /// Exact tree that owns the authority and its cancellation chain.
    pub tree: &'a RegionTree,
    /// Current caller clock boundary.
    pub now: TimestampNs,
}

fn capabilities() -> Vec<String> {
    let mut names: Vec<_> = GRANTS
        .iter()
        .map(|grant| grant.as_str().to_owned())
        .collect();
    names.sort();
    names
}

/// Conservative reservation for all requests, bounded codec/signing scratch and
/// the final receipt. Bytes are cumulative charged ceilings, not peak RSS or
/// measured network utilization. This function performs no I/O or allocation of media.
pub fn verification_budget(pin: S3ObjectPin, limits: S3Limits) -> Result<BudgetVector, S3Error> {
    pin.validate()?;
    limits.validate()?;
    let requests = pin.bytes.div_ceil(limits.response_bytes as u64).max(1);
    let mut budget = BudgetVector::ZERO;
    budget.bytes = limits
        .memory_per_call()
        .checked_mul(requests)
        .and_then(|bytes| bytes.checked_add(RECEIPT_RESERVATION))
        .ok_or(S3Error::Limit)?;
    budget.network_bytes = ((limits.header_bytes + limits.wire_bytes) as u64)
        .checked_mul(requests)
        .ok_or(S3Error::Limit)?;
    budget.storage_operations = requests;
    Ok(budget)
}

/// Immutable proof of a complete byte read at a particular time, not a promise
/// of future availability, replica count, encryption, or archive graph closure.
#[derive(Clone, Debug, PartialEq)]
pub struct S3VerificationReceipt {
    endpoint: ContentDigest,
    object: S3ObjectPin,
    etag_digest: ContentDigest,
    range_bytes: u64,
    authority: ContextAuthority,
    started_at: TimestampNs,
    verified_at: TimestampNs,
    consumed: BudgetVector,
}
impl S3VerificationReceipt {
    fn validate(&self) -> Result<(), S3Error> {
        self.object.validate()?;
        self.authority.validate().map_err(|_| S3Error::Protocol)?;
        if self.endpoint.algorithm() != DigestAlgorithm::Sha256
            || self.endpoint.bytes() == [0; 32]
            || self.etag_digest.algorithm() != DigestAlgorithm::Sha256
            || self.etag_digest.bytes() == [0; 32]
            || !(1024..=1024 * 1024).contains(&self.range_bytes)
            || self.authority.capabilities() != capabilities()
            || self.authority.anchor_universe != self.object.digest
            || self.authority.cancellation_reason.is_some()
            || self
                .authority
                .deadline
                .is_none_or(|deadline| self.verified_at >= deadline)
            || self.started_at > self.verified_at
            || !self.consumed.is_valid()
            || !self.consumed.fits_within(self.authority.budgets)
            || self.consumed.storage_operations
                != self.object.bytes.div_ceil(self.range_bytes).max(1)
            || self.consumed.bytes < RECEIPT_RESERVATION
            || self.consumed.network_bytes < self.object.bytes
        {
            return Err(S3Error::Protocol);
        }
        Ok(())
    }
    /// Strict canonical bytes suitable for separately authorized immutable custody.
    pub fn encode(&self) -> Result<Vec<u8>, S3Error> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(DOMAIN);
        e.digest(self.endpoint);
        e.digest(self.object.digest);
        e.u64(self.object.bytes);
        e.digest(self.etag_digest);
        e.u64(self.range_bytes);
        self.authority.encode_canonical(&mut e);
        e.i128(self.started_at.0);
        e.i128(self.verified_at.0);
        self.consumed.encode_canonical(&mut e);
        let bytes = e.finish_checked().map_err(|_| S3Error::Protocol)?;
        if bytes.len() > MAX_VERIFICATION_RECEIPT_BYTES {
            return Err(S3Error::Limit);
        }
        Ok(bytes)
    }
    /// Decode inert evidence. A receipt never reconstructs execution authority.
    pub fn decode(bytes: &[u8]) -> Result<Self, S3Error> {
        if bytes.len() > MAX_VERIFICATION_RECEIPT_BYTES {
            return Err(S3Error::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text().map_err(|_| S3Error::Protocol)? != DOMAIN {
            return Err(S3Error::Protocol);
        }
        let receipt = Self {
            endpoint: d.digest().map_err(|_| S3Error::Protocol)?,
            object: S3ObjectPin {
                digest: d.digest().map_err(|_| S3Error::Protocol)?,
                bytes: d.u64().map_err(|_| S3Error::Protocol)?,
            },
            etag_digest: d.digest().map_err(|_| S3Error::Protocol)?,
            range_bytes: d.u64().map_err(|_| S3Error::Protocol)?,
            authority: ContextAuthority::decode_canonical(&mut d).map_err(|_| S3Error::Protocol)?,
            started_at: TimestampNs(d.i128().map_err(|_| S3Error::Protocol)?),
            verified_at: TimestampNs(d.i128().map_err(|_| S3Error::Protocol)?),
            consumed: <BudgetVector as CanonicalDecode>::decode_canonical(&mut d)
                .map_err(|_| S3Error::Protocol)?,
        };
        d.ensure_finished().map_err(|_| S3Error::Protocol)?;
        if receipt.encode()? != bytes {
            return Err(S3Error::Protocol);
        }
        Ok(receipt)
    }
    /// Identity of the complete canonical evidence receipt.
    pub fn digest(&self) -> Result<ContentDigest, S3Error> {
        Ok(ContentDigest::sha256(&self.encode()?))
    }
    /// Exact source identity checked against the downloaded bytes.
    #[must_use]
    pub const fn object(&self) -> S3ObjectPin {
        self.object
    }
    /// Approved route identity; does not disclose the object key.
    #[must_use]
    pub const fn endpoint_digest(&self) -> ContentDigest {
        self.endpoint
    }
    /// Fresh authority recipe retained as inert evidence.
    #[must_use]
    pub fn authority(&self) -> &ContextAuthority {
        &self.authority
    }
    /// Latest checked clock boundary after full digest verification.
    #[must_use]
    pub const fn verified_at(&self) -> TimestampNs {
        self.verified_at
    }
    /// Charged ceilings, including unsuccessful wire work only if it ultimately completed.
    #[must_use]
    pub const fn consumed(&self) -> BudgetVector {
        self.consumed
    }
}

struct ReadBoundary<'a, 'owner, C> {
    endpoint: &'a S3Endpoint,
    clock: &'a mut C,
    io: S3ReadIo<'owner>,
    grants: GrantSet,
}
impl<C: S3ReadClock> ReadBoundary<'_, '_, C> {
    fn validate(&self) -> Result<(), S3Error> {
        let cx = &self.io.authority;
        if cx
            .is_cancel_requested(self.io.tree)
            .map_err(|_| S3Error::Authority)?
            || cx.kind() != RegionKind::ObjectStore
            || cx.grants() != &self.grants
        {
            return Err(S3Error::Authority);
        }
        let node = self
            .io
            .tree
            .get(cx.region())
            .map_err(|_| S3Error::Authority)?;
        if node.state != RegionState::Active
            || self.io.now < node.created_at
            || node.authority.capabilities() != capabilities()
        {
            return Err(S3Error::Authority);
        }
        if node
            .authority
            .deadline
            .is_none_or(|deadline| self.io.now >= deadline)
        {
            return Err(S3Error::Deadline);
        }
        for grant in GRANTS {
            cx.require_grant_for(grant, self.endpoint.resource())
                .map_err(|_| S3Error::Authority)?;
        }
        Ok(())
    }
    fn charge(&mut self, cost: BudgetVector) -> Result<(), S3Error> {
        self.checkpoint()?;
        self.io
            .authority
            .budget_mut(self.io.tree)
            .map_err(|_| S3Error::Authority)?
            .spend_vector(&cost)
            .map_err(|_| S3Error::Limit)
    }
}
impl<C: S3ReadClock> Boundary for ReadBoundary<'_, '_, C> {
    fn checkpoint(&mut self) -> Result<TimestampNs, S3Error> {
        self.validate()?;
        let now = self.clock.now(self.io.authority)?;
        if now < self.io.now {
            return Err(S3Error::Clock);
        }
        self.io.now = now;
        self.validate()?;
        Ok(now)
    }
    fn deadline(&self) -> Result<Option<TimestampNs>, S3Error> {
        Ok(self
            .io
            .tree
            .get(self.io.authority.region())
            .map_err(|_| S3Error::Authority)?
            .authority
            .deadline)
    }
}

fn strong_etag(value: &str) -> bool {
    (2..=1024).contains(&value.len())
        && value.starts_with('"')
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte) && *byte != b'"')
}

fn validate_range<'a>(
    reply: &'a http::Reply,
    pin: S3ObjectPin,
    offset: u64,
    len: u64,
    prior_etag: Option<&str>,
) -> Result<&'a str, S3Error> {
    reply.status(if pin.bytes == 0 { 200 } else { 206 })?;
    if reply.unique_header("content-length")? != len.to_string()
        || reply.0.body.len() as u64 != len
        || reply.optional_header("transfer-encoding")?.is_some()
        || reply
            .optional_header("content-encoding")?
            .is_some_and(|value| value != "identity")
        || reply
            .optional_header("x-amz-delete-marker")?
            .is_some_and(|value| value != "false")
    {
        return Err(S3Error::Protocol);
    }
    if pin.bytes == 0 {
        if reply.optional_header("content-range")?.is_some() {
            return Err(S3Error::Protocol);
        }
    } else if reply.unique_header("content-range")?
        != format!("bytes {}-{}/{}", offset, offset + len - 1, pin.bytes)
    {
        return Err(S3Error::Protocol);
    }
    let etag = reply.unique_header("etag")?;
    if !strong_etag(etag) || prior_etag.is_some_and(|previous| previous != etag) {
        return Err(S3Error::Protocol);
    }
    Ok(etag)
}

/// Read every byte through signed, bounded GET ranges, pin later ranges with
/// If-Match, and hash in source order against an independent full-object digest.
/// Empty objects use one exact zero-length GET. No HEAD, list, upload, retry,
/// redirect, DNS or media export occurs. Every request checks the same finite
/// owner deadline; boundaries cannot renew it. The caller retains the receipt
/// through its own filesystem authority before claiming durable proof.
pub fn verify_s3_object<C: S3ReadClock>(
    endpoint: &S3Endpoint,
    credentials: &S3Credentials,
    limits: S3Limits,
    clock: &mut C,
    io: S3ReadIo<'_>,
    pin: S3ObjectPin,
) -> Result<S3VerificationReceipt, S3Error> {
    let required = verification_budget(pin, limits)?;
    let mut grants = GrantSet::empty();
    for grant in GRANTS {
        grants = grants.with_scope(
            grant,
            [endpoint.resource().to_owned()].into_iter().collect(),
        );
    }
    let mut owner = ReadBoundary {
        endpoint,
        clock,
        io,
        grants,
    };
    owner.validate()?;
    if *owner.io.authority.budget().consumed() != BudgetVector::ZERO
        || !required.fits_within(owner.io.authority.budget().remaining())
    {
        return Err(S3Error::Limit);
    }
    let authority = owner
        .io
        .tree
        .get(owner.io.authority.region())
        .map_err(|_| S3Error::Authority)?
        .authority
        .clone();
    if authority.anchor_universe != pin.digest {
        return Err(S3Error::Authority);
    }
    let started_at = owner.io.now;
    let mut receipt_cost = BudgetVector::ZERO;
    receipt_cost.bytes = RECEIPT_RESERVATION;
    owner.charge(receipt_cost)?;
    let mut hasher = Sha256Hasher::new();
    let mut etag: Option<String> = None;
    let mut offset = 0;
    loop {
        let len = (pin.bytes - offset).min(limits.response_bytes as u64);
        let mut cost = BudgetVector::ZERO;
        cost.bytes = limits.memory_per_call();
        cost.network_bytes = (limits.header_bytes + limits.wire_bytes) as u64;
        cost.storage_operations = 1;
        owner.charge(cost)?;
        let mut headers = vec![("accept-encoding", "identity".to_owned())];
        if pin.bytes != 0 {
            headers.push(("range", format!("bytes={}-{}", offset, offset + len - 1)));
        }
        if let Some(value) = &etag {
            headers.push(("if-match", value.clone()));
        }
        let now = owner.checkpoint()?;
        let head = signing::request_head(
            endpoint,
            credentials,
            now,
            "GET",
            "",
            &headers,
            ContentDigest::sha256(b""),
            0,
            limits.header_bytes,
        )?;
        let reply =
            http::exchange_with_boundary(endpoint, limits, &mut owner, now, &head, &[], false)?;
        let observed_etag = validate_range(&reply, pin, offset, len, etag.as_deref())?;
        if etag.is_none() {
            etag = Some(observed_etag.to_owned());
        }
        hasher.update(&reply.0.body);
        offset += len;
        if offset == pin.bytes {
            break;
        }
    }
    let digest = ContentDigest::new(
        DigestAlgorithm::Sha256,
        hasher.finalize().map_err(|_| S3Error::Limit)?,
    );
    if digest != pin.digest {
        return Err(S3Error::Integrity);
    }
    let verified_at = owner.checkpoint()?;
    let receipt = S3VerificationReceipt {
        endpoint: endpoint.digest(),
        object: pin,
        etag_digest: ContentDigest::sha256(etag.ok_or(S3Error::Protocol)?.as_bytes()),
        range_bytes: limits.response_bytes as u64,
        authority,
        started_at,
        verified_at,
        consumed: *owner.io.authority.budget().consumed(),
    };
    receipt.validate()?;
    Ok(receipt)
}
