#![forbid(unsafe_code)]
//! Native, serial S3-compatible multipart writes to an explicitly approved local endpoint.
//!
//! This is the wire adapter for the existing durable multipart owner, not another
//! upload state machine or an archive-root/retrievability claim. Each operation
//! uses its real TransportCx and one owned, bounded socket. Public-address
//! plaintext, DNS, redirects, credential discovery, automatic retries and TLS
//! are deliberately unsupported. A lost acknowledgement remains uncertain;
//! a read-only HEAD bound to journal origin, intent and checksum can prove an
//! uncertain completion. Legacy objects without origin metadata stay uncertain.
//! A complete checksum-bound ListParts response can also recover a lost part
//! acknowledgement for a pending, unexpired owner. Missing parts stay uncertain.
//! Absence from an object listing cannot authorize another create or complete.
//! Independent retrieval uses a fresh media-read owner and sequential signed
//! ranges pinned to one opaque ETag; the owner hashes the returned bytes itself.

mod http;
mod inventory;
mod retrieval;
mod signing;
/// Separately authorized verification without an upload journal.
pub mod verification;
mod xml;

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use fss_core::{
    BudgetVector, CanonicalEncoder, ContentDigest, DigestAlgorithm, RuntimeGrant, TimestampNs,
};
use fss_object::multipart::{
    ETag, MultipartPhase, MultipartRecovery, MultipartTransport, PartReceipt, ProviderUploadState,
    Reconciliation, TransportCx, TransportOperation, UploadId, UploadIntent,
};
use fss_object::planner::PlannedChunk;
use zeroize::Zeroizing;

/// Payload-free transport refusal. No credential, object key or provider body is included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum S3Error {
    /// Endpoint, credential shape or bounds are invalid.
    Configuration,
    /// The exact current scoped authority refused the operation.
    Authority,
    /// Supplied clock is invalid, reversed or unavailable.
    Clock,
    /// The bounded exchange elapsed; its remote outcome may be unknown.
    Deadline,
    /// A fixed memory, wire, part or I/O-count bound was reached.
    Limit,
    /// The socket could not be opened, read, written or configured.
    Io,
    /// HTTP framing, XML or independent checksum did not establish success.
    Protocol,
    /// Downloaded bytes did not match the independently supplied object identity.
    Integrity,
    /// A provider returned a non-success status; the upload owner remains uncertain.
    Status(u16),
    /// This adapter is already bound to another intent or upload.
    Binding,
    /// A previous dispatch requires independent reconciliation.
    Uncertain,
}
impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S3 transport refused: {self:?}")
    }
}
impl std::error::Error for S3Error {}

/// Pinned path-style local S3 route. Private address space is not authentication;
/// the independent approval must cover this exact trust boundary and route.
#[derive(Clone)]
pub struct S3Endpoint {
    peer: SocketAddr,
    host: String,
    region: String,
    bucket: String,
    key: String,
    digest: ContentDigest,
    resource: String,
}
impl S3Endpoint {
    /// Validate a local/loopback peer, explicit Host, region, bucket and exact key.
    /// The host is sent unchanged and never resolved. Keys are not normalized.
    pub fn new(
        peer: SocketAddr,
        host: &str,
        region: &str,
        bucket: &str,
        key: &str,
        plaintext_approval: ContentDigest,
    ) -> Result<Self, S3Error> {
        let local = match peer.ip() {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
            }
        };
        if !local
            || peer.port() == 0
            || host.is_empty()
            || host.len() > 253
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
            || region.is_empty()
            || region.len() > 63
            || !region
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !(3..=63).contains(&bucket.len())
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
            || !bucket.as_bytes()[0].is_ascii_alphanumeric()
            || !bucket.as_bytes()[bucket.len() - 1].is_ascii_alphanumeric()
            || key.is_empty()
            || key.len() > 1024
            || key.chars().any(char::is_control)
            || plaintext_approval.algorithm() != DigestAlgorithm::Sha256
            || plaintext_approval.bytes() == [0; 32]
        {
            return Err(S3Error::Configuration);
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.s3_local_endpoint.v1");
        e.text(&peer.to_string());
        e.text(host);
        e.text(region);
        e.text(bucket);
        e.text(key);
        e.digest(plaintext_approval);
        let digest = ContentDigest::sha256(&e.finish());
        Ok(Self {
            peer,
            host: host.to_owned(),
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            digest,
            resource: format!("archive:s3:{}", signing::hex(&digest.bytes())),
        })
    }

    /// Exact route-specific resource used for network, object and secret grants.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Route and independent plaintext-approval binding; no secret is included.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}
impl fmt::Debug for S3Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Endpoint")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// An ephemeral credential lease supplied by the authorized caller. No ambient
/// environment/config lookup occurs. All fields and owned parser input zeroize.
pub struct S3Credentials {
    access_key: Zeroizing<String>,
    secret_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}
impl S3Credentials {
    /// Accept bounded explicit credential values. The caller owns resolution,
    /// expiry and revocation; signing separately checks AdapterAuth each time.
    pub fn new(
        access_key: &str,
        secret_key: &str,
        session_token: Option<&str>,
    ) -> Result<Self, S3Error> {
        if access_key.is_empty()
            || access_key.len() > 128
            || !access_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            || secret_key.is_empty()
            || secret_key.len() > 256
            || !secret_key.bytes().all(|b| (33..=126).contains(&b))
            || session_token.is_some_and(|token| {
                token.is_empty()
                    || token.len() > 4096
                    || !token.bytes().all(|b| (33..=126).contains(&b))
            })
        {
            return Err(S3Error::Configuration);
        }
        Ok(Self {
            access_key: Zeroizing::new(access_key.to_owned()),
            secret_key: Zeroizing::new(secret_key.to_owned()),
            session_token: session_token.map(|value| Zeroizing::new(value.to_owned())),
        })
    }

    /// Consume a secret file containing two or three LF-terminated UTF-8 lines:
    /// access key, secret key, optional session token. CR and control bytes refuse.
    /// Input is zeroized even on malformed, oversized or invalid-UTF-8 data.
    pub fn from_lines(bytes: Vec<u8>) -> Result<Self, S3Error> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > 8192 || !bytes.ends_with(b"\n") {
            return Err(S3Error::Configuration);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| S3Error::Configuration)?;
        let mut lines = text[..text.len() - 1].split('\n');
        let access = lines.next().ok_or(S3Error::Configuration)?;
        let secret = lines.next().ok_or(S3Error::Configuration)?;
        let token = lines.next();
        if lines.next().is_some() {
            return Err(S3Error::Configuration);
        }
        Self::new(access, secret, token)
    }
}
impl fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("S3Credentials([redacted])")
    }
}

/// Caller-owned clock boundary. A current UTC sample is used for signing and
/// operation deadlines. Clock errors and regressions never restart an exchange.
pub trait S3Clock {
    /// Observe time under the actual admitted upload context.
    fn now(&mut self, cx: &TransportCx<'_>) -> Result<TimestampNs, S3Error>;
}

/// Hard bounds for one request/response. Payload bytes remain charged by the
/// multipart protocol. This adapter additionally charges all framing/control
/// bytes and bounded parsing/signer allocations before network I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct S3Limits {
    /// Request head and each complete response head, at most 32 KiB.
    pub header_bytes: usize,
    /// Transfer-decoded response body, at most 1 MiB.
    pub response_bytes: usize,
    /// Entire response including chunked framing, at most 2 MiB.
    pub wire_bytes: usize,
    /// One socket read/write offer, at most 64 KiB.
    pub io_bytes: usize,
    /// Total connect/configure/read/write calls, at most one million.
    pub io_calls: u64,
    /// One connect timeout, at most five seconds.
    pub connect_timeout_ns: u64,
    /// One read/write timeout, at most one second.
    pub io_timeout_ns: u64,
    /// Whole operation timeout, including cleanup, at most five minutes.
    pub exchange_timeout_ns: u64,
}
impl Default for S3Limits {
    fn default() -> Self {
        Self {
            header_bytes: 16 * 1024,
            response_bytes: 256 * 1024,
            wire_bytes: 512 * 1024,
            io_bytes: 64 * 1024,
            io_calls: 65_536,
            connect_timeout_ns: 3_000_000_000,
            io_timeout_ns: 1_000_000_000,
            exchange_timeout_ns: 120_000_000_000,
        }
    }
}
impl S3Limits {
    fn validate(self) -> Result<(), S3Error> {
        if !(4096..=32 * 1024).contains(&self.header_bytes)
            || !(1024..=1024 * 1024).contains(&self.response_bytes)
            || self.wire_bytes < self.response_bytes + self.header_bytes
            || self.wire_bytes > 2 * 1024 * 1024
            || !(1..=64 * 1024).contains(&self.io_bytes)
            || !(8..=1_000_000).contains(&self.io_calls)
            || !(1..=5_000_000_000).contains(&self.connect_timeout_ns)
            || !(1..=1_000_000_000).contains(&self.io_timeout_ns)
            || !(1..=300_000_000_000).contains(&self.exchange_timeout_ns)
        {
            return Err(S3Error::Configuration);
        }
        Ok(())
    }

    fn memory_per_call(self) -> u64 {
        // Includes codec, XML, signing and bounded response copies. Source payload
        // remains borrowed; it is never copied into a complete HTTP request.
        (self.response_bytes as u64 + self.header_bytes as u64) * 8 + 32 * 1024
    }

    /// Conservative additional reservation for parts plus five lifecycle calls.
    /// Add this to minimum_upload_budget and separately authorized source/journal
    /// work. It does not replenish allowance on recovery or include payload twice.
    pub fn overhead_budget(self, part_count: usize) -> Result<BudgetVector, S3Error> {
        self.validate()?;
        if !(1..=10_000).contains(&part_count) {
            return Err(S3Error::Limit);
        }
        let calls = part_count as u64 + 5;
        let completion = xml::completion_bound(part_count)? as u64;
        let observation =
            part_count as u64 * (std::mem::size_of::<PartReceipt>() as u64 + 1024 + 32) + 1024;
        let mut budget = BudgetVector::ZERO;
        budget.bytes = self
            .memory_per_call()
            .checked_mul(calls)
            .and_then(|n| n.checked_add(completion * 2 + observation + part_count as u64 * 256))
            .ok_or(S3Error::Limit)?;
        budget.network_bytes = ((self.header_bytes + self.wire_bytes) as u64)
            .checked_mul(calls)
            .and_then(|n| n.checked_add(completion))
            .ok_or(S3Error::Limit)?;
        Ok(budget)
    }
}

/// One serial wire owner for one immutable multipart intent. The protocol and
/// durable journal remain authoritative. An uncertain adapter never retries a
/// mutation; use the same durable recovery or retain explicit indeterminacy.
pub struct NativeS3Transport<C: S3Clock> {
    endpoint: S3Endpoint,
    credentials: S3Credentials,
    limits: S3Limits,
    clock: C,
    intent: Option<UploadIntent>,
    origin: Option<ContentDigest>,
    upload: Option<UploadId>,
    intended: BTreeMap<u64, (u64, ContentDigest)>,
    parts: BTreeMap<u64, PartReceipt>,
    confirmed_bytes: u64,
    phase: MultipartPhase,
    retrieval: retrieval::ReadState,
}
impl<C: S3Clock> fmt::Debug for NativeS3Transport<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeS3Transport")
            .field("endpoint", &self.endpoint.digest)
            .field("phase", &self.phase)
            .field("confirmed_parts", &self.parts.len())
            .finish_non_exhaustive()
    }
}
impl<C: S3Clock> NativeS3Transport<C> {
    /// Pure preparation. This creates no socket and performs no credential lookup.
    pub fn new(
        endpoint: S3Endpoint,
        credentials: S3Credentials,
        limits: S3Limits,
        clock: C,
    ) -> Result<Self, S3Error> {
        limits.validate()?;
        Ok(Self {
            endpoint,
            credentials,
            limits,
            clock,
            intent: None,
            origin: None,
            upload: None,
            intended: BTreeMap::new(),
            parts: BTreeMap::new(),
            confirmed_bytes: 0,
            phase: MultipartPhase::Prepared,
            retrieval: retrieval::ReadState::default(),
        })
    }

    /// Bind inert verified journal data. It grants no authority or network I/O.
    /// Known active uploads can resume; uncertain records remain uncertain and
    /// cannot mint another upload ID or blindly republish the object.
    pub fn from_recovery(
        endpoint: S3Endpoint,
        credentials: S3Credentials,
        limits: S3Limits,
        clock: C,
        recovery: &MultipartRecovery,
    ) -> Result<Self, S3Error> {
        if recovery.intent().resource() != endpoint.resource()
            || recovery.owner_metadata().is_empty()
        {
            return Err(S3Error::Binding);
        }
        let mut result = Self::new(endpoint, credentials, limits, clock)?;
        result.intent = Some(recovery.intent().clone());
        result.origin = recovery.origin_binding();
        result.upload = recovery.upload_id().cloned();
        for (index, digest) in recovery.intended_parts() {
            let position = usize::try_from(index).map_err(|_| S3Error::Binding)?;
            let chunk = recovery
                .plan()
                .chunks
                .get(position)
                .ok_or(S3Error::Binding)?;
            if index >= 10_000 || chunk.index != index {
                return Err(S3Error::Binding);
            }
            result.intended.insert(index, (chunk.len, digest));
        }
        result.parts = recovery
            .part_receipts()
            .map(|part| (part.index, part.clone()))
            .collect();
        for part in result.parts.values() {
            let index = usize::try_from(part.index).map_err(|_| S3Error::Binding)?;
            let chunk = recovery.plan().chunks.get(index).ok_or(S3Error::Binding)?;
            if result.intended.get(&part.index) != Some(&(chunk.len, part.content_digest)) {
                return Err(S3Error::Binding);
            }
            result.confirmed_bytes = result
                .confirmed_bytes
                .checked_add(chunk.len)
                .ok_or(S3Error::Limit)?;
        }
        if matches!(
            recovery.phase(),
            MultipartPhase::Uncertain(TransportOperation::Complete) | MultipartPhase::Completed
        ) && (result.parts.len() != recovery.plan().chunks.len()
            || result.confirmed_bytes != recovery.plan().object_bytes)
        {
            return Err(S3Error::Binding);
        }
        result.phase = recovery.phase();
        Ok(result)
    }

    fn check(
        &mut self,
        cx: &mut TransportCx<'_>,
        operation: TransportOperation,
    ) -> Result<TimestampNs, S3Error> {
        if cx.resource() != self.endpoint.resource() || cx.operation() != operation {
            return Err(S3Error::Binding);
        }
        if self.intent.is_some() && self.origin != cx.origin_binding() {
            return Err(S3Error::Binding);
        }
        // The protocol-only v1 recovery mask covers object/network grants.
        // Native signing additionally uses AdapterAuth. Only StagedUpload's
        // validated owner metadata durably preserves its dynamic revocation.
        if cx.is_durable() && !cx.has_durable_upload_owner() {
            return Err(S3Error::Binding);
        }
        cx.checkpoint(cx.now()).map_err(|_| S3Error::Authority)?;
        cx.authority()
            .require_grant_for(RuntimeGrant::AdapterAuth, self.endpoint.resource())
            .map_err(|_| S3Error::Authority)?;
        let now = self.clock.now(cx)?;
        cx.checkpoint(now).map_err(|_| S3Error::Authority)?;
        Ok(now)
    }

    fn bind(
        &mut self,
        intent: &UploadIntent,
        origin: Option<ContentDigest>,
    ) -> Result<(), S3Error> {
        if intent.resource() != self.endpoint.resource()
            || self.intent.as_ref().is_some_and(|bound| bound != intent)
            || (self.intent.is_some() && self.origin != origin)
            || origin.is_some_and(|value| {
                value.algorithm() != DigestAlgorithm::Sha256
                    || value.bytes() == [0; 32]
                    || value.is_laboratory()
            })
        {
            return Err(S3Error::Binding);
        }
        if self.intent.is_none() {
            self.intent = Some(intent.clone());
            self.origin = origin;
        }
        Ok(())
    }

    fn active(&self, upload: &UploadId) -> Result<(), S3Error> {
        if self.phase != MultipartPhase::Uploading {
            return Err(S3Error::Uncertain);
        }
        if self.upload.as_ref() != Some(upload) {
            return Err(S3Error::Binding);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn exchange(
        &mut self,
        cx: &mut TransportCx<'_>,
        method: &str,
        query: &str,
        headers: &[(&'static str, String)],
        body: &[u8],
        digest: ContentDigest,
        payload: bool,
    ) -> Result<http::Reply, S3Error> {
        let operation = cx.operation();
        let now = self.check(cx, operation)?;
        // Reserve the full bounded response, all framing and scratch before
        // allocation or socket creation. A payload is already protocol-charged.
        let extra_body = if payload { 0 } else { body.len() as u64 };
        cx.charge_io(
            now,
            self.limits.memory_per_call(),
            (self.limits.header_bytes + self.limits.wire_bytes) as u64 + extra_body,
        )
        .map_err(|_| S3Error::Authority)?;
        let head = signing::request_head(
            &self.endpoint,
            &self.credentials,
            now,
            method,
            query,
            headers,
            digest,
            body.len(),
            self.limits.header_bytes,
        )?;
        http::exchange(
            &self.endpoint,
            self.limits,
            &mut self.clock,
            cx,
            now,
            &head,
            body,
            method == "HEAD",
        )
    }

    fn initiate_inner(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<UploadId, S3Error> {
        self.check(cx, TransportOperation::Initiate)?;
        self.bind(intent, cx.origin_binding())?;
        if self.phase == MultipartPhase::Uploading {
            return self.upload.clone().ok_or(S3Error::Binding);
        }
        if self.phase != MultipartPhase::Prepared {
            return Err(S3Error::Uncertain);
        }
        self.phase = MultipartPhase::Uncertain(TransportOperation::Initiate);
        let mut headers = vec![
            ("x-amz-checksum-algorithm", "SHA256".to_owned()),
            ("x-amz-checksum-type", "COMPOSITE".to_owned()),
            (
                "x-amz-meta-fss-intent",
                signing::hex(&intent.digest().bytes()),
            ),
            (
                "x-amz-meta-fss-plan",
                signing::hex(&intent.plan_digest().bytes()),
            ),
            (
                "x-amz-meta-fss-root",
                signing::hex(&intent.manifest_root().bytes()),
            ),
        ];
        if let Some(origin) = self.origin {
            headers.push(("x-amz-meta-fss-origin", signing::hex(&origin.bytes())));
        }
        let response = self.exchange(
            cx,
            "POST",
            "uploads=",
            &headers,
            &[],
            ContentDigest::sha256(b""),
            false,
        )?;
        response.status(200)?;
        let fields = xml::response(&response.0.body, "InitiateMultipartUploadResult")?;
        xml::target(&fields, &self.endpoint.bucket, &self.endpoint.key)?;
        let id = xml::required(&fields, "UploadId")?;
        if id.is_empty() || id.len() > 1024 || id.chars().any(char::is_control) {
            return Err(S3Error::Protocol);
        }
        let upload = UploadId(id.to_owned());
        self.upload = Some(upload.clone());
        self.phase = MultipartPhase::Uploading;
        Ok(upload)
    }

    fn upload_inner(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        content_digest: ContentDigest,
    ) -> Result<PartReceipt, S3Error> {
        self.check(cx, TransportOperation::UploadPart)?;
        self.active(upload)?;
        if chunk.index >= 10_000
            || chunk.len != bytes.len() as u64
            || bytes.len() > 64 * 1024 * 1024
            || ContentDigest::sha256(bytes) != content_digest
        {
            return Err(S3Error::Configuration);
        }
        if let Some(part) = self.parts.get(&chunk.index) {
            return if part.content_digest == content_digest {
                Ok(part.clone())
            } else {
                Err(S3Error::Binding)
            };
        }
        let intended = (chunk.len, content_digest);
        if self
            .intended
            .get(&chunk.index)
            .is_some_and(|original| *original != intended)
        {
            return Err(S3Error::Binding);
        }
        if let std::collections::btree_map::Entry::Vacant(e) = self.intended.entry(chunk.index) {
            // Admit the retained map entry before allocation. Its lifetime
            // includes a lost ACK, so recovery can compare the original bytes.
            cx.charge_io(cx.now(), 256, 0)
                .map_err(|_| S3Error::Authority)?;
            e.insert(intended);
        }
        let confirmed_bytes = self
            .confirmed_bytes
            .checked_add(chunk.len)
            .ok_or(S3Error::Limit)?;
        self.phase = MultipartPhase::Uncertain(TransportOperation::UploadPart);
        let checksum = signing::base64(&content_digest.bytes());
        let part_number = (chunk.index + 1).to_string();
        let query = signing::query(&[("partNumber", &part_number), ("uploadId", &upload.0)]);
        let response = self.exchange(
            cx,
            "PUT",
            &query,
            &[("x-amz-checksum-sha256", checksum.clone())],
            bytes,
            content_digest,
            true,
        )?;
        response.status(200)?;
        if !response.0.body.is_empty()
            || response.unique_header("x-amz-checksum-sha256")? != checksum
        {
            return Err(S3Error::Protocol);
        }
        let etag = response.unique_header("etag")?;
        if etag.is_empty() || etag.len() > 1024 || etag.chars().any(char::is_control) {
            return Err(S3Error::Protocol);
        }
        let receipt = PartReceipt {
            index: chunk.index,
            content_digest,
            etag: ETag(etag.to_owned()),
        };
        self.parts.insert(chunk.index, receipt.clone());
        self.confirmed_bytes = confirmed_bytes;
        self.phase = MultipartPhase::Uploading;
        Ok(receipt)
    }

    fn complete_inner(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
        parts: &[PartReceipt],
    ) -> Result<(), S3Error> {
        let now = self.check(cx, TransportOperation::Complete)?;
        self.bind(intent, cx.origin_binding())?;
        self.active(upload)?;
        if parts.len() != self.parts.len()
            || parts.is_empty()
            || parts.len() > 10_000
            || parts.iter().enumerate().any(|(index, part)| {
                part.index != index as u64 || self.parts.get(&part.index) != Some(part)
            })
        {
            return Err(S3Error::Binding);
        }
        let bound = xml::completion_bound(parts.len())?;
        cx.charge_io(now, bound as u64 * 2, 0)
            .map_err(|_| S3Error::Authority)?;
        let body = xml::completion(parts)?;
        let digest = ContentDigest::sha256(&body);
        self.phase = MultipartPhase::Uncertain(TransportOperation::Complete);
        let query = signing::query(&[("uploadId", &upload.0)]);
        let response = self.exchange(
            cx,
            "POST",
            &query,
            &[
                ("content-type", "application/xml".to_owned()),
                ("if-none-match", "*".to_owned()),
                ("x-amz-checksum-type", "COMPOSITE".to_owned()),
            ],
            &body,
            digest,
            false,
        )?;
        response.status(200)?;
        // HTTP 200 may contain whitespace followed by Error. Only the complete,
        // bounded success document plus its independently returned checksum counts.
        let fields = xml::response(&response.0.body, "CompleteMultipartUploadResult")?;
        xml::target(&fields, &self.endpoint.bucket, &self.endpoint.key)?;
        let etag = xml::required(&fields, "ETag")?;
        if etag.is_empty()
            || etag.len() > 1024
            || xml::required(&fields, "ChecksumSHA256")? != xml::composite_checksum(parts.iter())
            || fields
                .get("ChecksumType")
                .is_some_and(|kind| kind != "COMPOSITE")
        {
            return Err(S3Error::Protocol);
        }
        self.phase = MultipartPhase::Completed;
        Ok(())
    }

    fn abort_inner(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
    ) -> Result<(), S3Error> {
        self.check(cx, TransportOperation::Abort)?;
        self.bind(intent, cx.origin_binding())?;
        self.active(upload)?;
        // All earlier sends had full acknowledgements and this owner never
        // dispatches concurrently. An uncertain earlier send cannot reach here.
        self.phase = MultipartPhase::Uncertain(TransportOperation::Abort);
        let query = signing::query(&[("uploadId", &upload.0)]);
        let response = self.exchange(
            cx,
            "DELETE",
            &query,
            &[],
            &[],
            ContentDigest::sha256(b""),
            false,
        )?;
        response.status(204)?;
        if !response.0.body.is_empty() {
            return Err(S3Error::Protocol);
        }
        self.phase = MultipartPhase::Aborted;
        Ok(())
    }

    fn reconcile_inner(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, S3Error> {
        if cx.is_media_retrieval() {
            return Err(S3Error::Binding);
        }
        self.check(cx, TransportOperation::Reconcile)?;
        self.bind(intent, cx.origin_binding())?;
        let mut observation = Reconciliation {
            intent_digest: intent.digest(),
            state: ProviderUploadState::Unknown,
        };
        if self.phase == MultipartPhase::Uncertain(TransportOperation::UploadPart) {
            return self.reconcile_part(cx, intent);
        }
        // A standard S3 listing cannot establish that a lost initiation or
        // abort did not run. Completion requires the complete acknowledged
        // inventory and this journal's initiation metadata for a positive proof.
        if self.phase != MultipartPhase::Uncertain(TransportOperation::Complete) {
            return Ok(observation);
        }
        // An identical semantic intent can be attempted by another journal.
        // Only an origin committed before this initiation distinguishes its
        // completed object from a prior attempt that left this upload active.
        // Legacy and non-durable uploads therefore cannot acquire positive
        // completion evidence from object metadata alone.
        let Some(origin) = self.origin else {
            return Ok(observation);
        };
        if self.upload.is_none()
            || self.parts.is_empty()
            || self.parts.len() > 10_000
            || self
                .parts
                .values()
                .enumerate()
                .any(|(index, part)| part.index != index as u64)
        {
            return Err(S3Error::Binding);
        }
        let response = self.exchange(
            cx,
            "HEAD",
            "",
            &[("x-amz-checksum-mode", "ENABLED".to_owned())],
            &[],
            ContentDigest::sha256(b""),
            false,
        )?;
        // Missing, denied, redirected or conflicting objects say nothing about
        // whether the original request committed. No observation here ever
        // authorizes another Complete, UploadPart, Abort or Initiate request.
        if response.0.status != 200 {
            return Ok(observation);
        }
        // The checksum scratch scales with part count, independently of the
        // configured response/header bounds. Admit it before allocating it.
        cx.charge_io(cx.now(), self.parts.len() as u64 * 32, 0)
            .map_err(|_| S3Error::Authority)?;
        for (name, expected) in [
            (
                "x-amz-meta-fss-intent",
                signing::hex(&intent.digest().bytes()),
            ),
            (
                "x-amz-meta-fss-plan",
                signing::hex(&intent.plan_digest().bytes()),
            ),
            (
                "x-amz-meta-fss-root",
                signing::hex(&intent.manifest_root().bytes()),
            ),
            ("x-amz-meta-fss-origin", signing::hex(&origin.bytes())),
            (
                "x-amz-checksum-sha256",
                xml::composite_checksum(self.parts.values()),
            ),
            ("x-amz-checksum-type", "COMPOSITE".to_owned()),
            ("content-length", self.confirmed_bytes.to_string()),
        ] {
            if response.optional_header(name)? != Some(expected.as_str()) {
                return Ok(observation);
            }
        }
        if response.optional_header("content-range")?.is_some()
            || response
                .optional_header("x-amz-delete-marker")?
                .is_some_and(|value| value != "false")
            || !response.optional_header("etag")?.is_some_and(|value| {
                !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control)
            })
        {
            return Ok(observation);
        }
        let upload = self.upload.as_ref().ok_or(S3Error::Binding)?;
        let inventory_bytes =
            self.parts
                .values()
                .try_fold(upload.0.len() as u64, |sum, part| {
                    sum.checked_add(
                        std::mem::size_of::<PartReceipt>() as u64 + part.etag.0.len() as u64,
                    )
                    .ok_or(S3Error::Limit)
                })?;
        cx.charge_io(cx.now(), inventory_bytes, 0)
            .map_err(|_| S3Error::Authority)?;
        observation.state = ProviderUploadState::Completed {
            upload: upload.clone(),
            manifest_root: intent.manifest_root(),
            parts: self.parts.values().cloned().collect(),
        };
        // The owning protocol validates and durably records this observation.
        // Keep the adapter's uncertain phase so a failed journal append or a
        // separately owned read-only observation cannot reactivate old work.
        Ok(observation)
    }

    fn reconcile_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, S3Error> {
        let mut observation = Reconciliation {
            intent_digest: intent.digest(),
            state: ProviderUploadState::Unknown,
        };
        // This first slice belongs to the original pending mutation owner.
        // Observing a closed owner cannot resurrect it or confer write grants.
        if self.origin.is_none() || !cx.is_durable() || cx.is_read_only_observation() {
            return Ok(observation);
        }
        cx.require_forward_reconciliation()
            .map_err(|_| S3Error::Authority)?;
        // A nonterminal observation must leave one operation and native
        // exchange allowance for aborting staging after a cold reopen.
        let remaining = cx.authority().budget().remaining();
        let memory_floor = self.limits.memory_per_call();
        let wire_floor = (self.limits.header_bytes + self.limits.wire_bytes) as u64;
        if remaining.bytes < memory_floor * 2 || remaining.network_bytes < wire_floor * 2 {
            return Err(S3Error::Authority);
        }
        if self.intended.is_empty()
            || self.intended.len() > inventory::MAX_PARTS
            || self.intended.len() != self.parts.len() + 1
        {
            return Ok(observation);
        }
        let upload = self.upload.as_ref().ok_or(S3Error::Binding)?;
        let query = signing::query(&[
            ("max-parts", "1000"),
            ("part-number-marker", "0"),
            ("uploadId", &upload.0),
        ]);
        let response = self.exchange(
            cx,
            "GET",
            &query,
            &[],
            &[],
            ContentDigest::sha256(b""),
            false,
        )?;
        if response.0.status != 200 {
            return Ok(observation);
        }
        let upload = self.upload.as_ref().ok_or(S3Error::Binding)?;
        let Some(parts) = inventory::verify(
            &response.0.body,
            &self.endpoint.bucket,
            &self.endpoint.key,
            upload,
            &self.intended,
            &self.parts,
        )?
        else {
            return Ok(observation);
        };
        // Parsing and checksum comparison cannot hide an expiry or revocation.
        self.check(cx, TransportOperation::Reconcile)?;
        observation.state = ProviderUploadState::Active {
            upload: self.upload.clone().ok_or(S3Error::Binding)?,
            parts,
        };
        // The protocol must durably accept this inventory before any new work.
        // Keep the adapter uncertain; cold recovery from its committed journal
        // creates the next active adapter. No same-call mutation is dispatched.
        Ok(observation)
    }
}
impl<C: S3Clock> MultipartTransport for NativeS3Transport<C> {
    fn initiate(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<UploadId, String> {
        self.initiate_inner(cx, intent)
            .map_err(|error| error.to_string())
    }

    fn upload_part(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        chunk: &PlannedChunk,
        bytes: &[u8],
        content_digest: ContentDigest,
    ) -> Result<PartReceipt, String> {
        self.upload_inner(cx, upload, chunk, bytes, content_digest)
            .map_err(|error| error.to_string())
    }

    fn complete(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
        parts: &[PartReceipt],
    ) -> Result<(), String> {
        self.complete_inner(cx, upload, intent, parts)
            .map_err(|error| error.to_string())
    }

    fn abort(
        &mut self,
        cx: &mut TransportCx<'_>,
        upload: &UploadId,
        intent: &UploadIntent,
    ) -> Result<(), String> {
        self.abort_inner(cx, upload, intent)
            .map_err(|error| error.to_string())
    }

    fn reconcile(
        &mut self,
        cx: &mut TransportCx<'_>,
        intent: &UploadIntent,
    ) -> Result<Reconciliation, String> {
        self.reconcile_inner(cx, intent)
            .map_err(|error| error.to_string())
    }
}
