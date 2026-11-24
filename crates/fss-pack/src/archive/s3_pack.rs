#![forbid(unsafe_code)]
//! Pure-Rust S3 / Cloudflare R2 / Backblaze B2 compatible cold pack transport boundary.
//!
//! Security and authority invariants:
//! - Explicit pinned `SocketAddr` + `Host` + operator `endpoint_approval` digest; ZERO ambient DNS.
//! - Zero redirects (HTTP 3xx responses fail closed).
//! - Explicit `AdapterFamily::ArchiveS3` [`SecretScope`] credentials held in [`SecretBytes`] /
//!   [`Zeroizing`]; ZERO ambient environment variable or filesystem credential discovery.
//! - ZERO credentials, signing keys, or raw provider bodies in error messages or `Debug` output.

use std::fmt;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use fss_core::{CanonicalEncoder, ContentDigest, DigestAlgorithm, TimestampNs};
use fss_vault::{
    AdapterFamily, REDACTED_SECRET_DISPLAY, SecretAccessCx, SecretBytes, SecretId, SecretOperation,
    SecretScope, SecretStore,
};
use zeroize::Zeroizing;

use crate::archive::manifest::ColdProviderKind;
use crate::archive::s3_wire::{
    HttpReply, build_complete_multipart_xml, build_sigv4_request_head, canonical_query,
    encode_base64, parse_flat_s3_xml, read_http1_response, validate_object_key, write_socket_all,
};
use crate::error::PackError;

/// Canonical digest domain binding an explicitly approved cold S3/R2/B2 endpoint route.
pub const PACK_COLD_ENDPOINT_DOMAIN: &str = "fss.pack.cold_endpoint.v1";

/// Explicitly approved S3 / Cloudflare R2 / Backblaze B2 compatible cold endpoint.
///
/// Connects directly to `peer` with zero ambient DNS lookup and sends `host` unchanged in HTTP/1.1.
#[derive(Clone)]
pub struct ColdS3Endpoint {
    provider: ColdProviderKind,
    peer: SocketAddr,
    host: String,
    region: String,
    bucket: String,
    endpoint_approval: ContentDigest,
    endpoint_digest: ContentDigest,
}

impl ColdS3Endpoint {
    /// Validates and constructs an explicitly approved local/loopback/private cold S3 endpoint.
    pub fn new_local_approved(
        provider: ColdProviderKind,
        peer: SocketAddr,
        host: &str,
        region: &str,
        bucket: &str,
        endpoint_approval: ContentDigest,
    ) -> Result<Self, PackError> {
        let is_local = match peer.ip() {
            IpAddr::V4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
            }
        };
        if !is_local {
            return Err(PackError::ArchiveTransport {
                detail: "plaintext HTTP/1.1 cold transport refuses non-local peer IP".to_owned(),
            });
        }
        Self::build_validated(provider, peer, host, region, bucket, endpoint_approval)
    }

    fn build_validated(
        provider: ColdProviderKind,
        peer: SocketAddr,
        host: &str,
        region: &str,
        bucket: &str,
        endpoint_approval: ContentDigest,
    ) -> Result<Self, PackError> {
        if peer.port() == 0
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
            || endpoint_approval.algorithm() != DigestAlgorithm::Sha256
            || endpoint_approval.bytes() == [0_u8; 32]
        {
            return Err(PackError::InvalidConfig {
                detail: "invalid cold S3/R2/B2 endpoint configuration or approval digest"
                    .to_owned(),
            });
        }

        let mut enc = CanonicalEncoder::new();
        enc.text(PACK_COLD_ENDPOINT_DOMAIN);
        enc.tag(provider.to_tag());
        enc.text(&peer.to_string());
        enc.text(host);
        enc.text(region);
        enc.text(bucket);
        enc.digest(endpoint_approval);
        let endpoint_digest = ContentDigest::sha256(&enc.finish_checked()?);

        Ok(Self {
            provider,
            peer,
            host: host.to_owned(),
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            endpoint_approval,
            endpoint_digest,
        })
    }

    /// Returns the provider family (`AwsS3`, `CloudflareR2`, `BackblazeB2`, `LocalS3Compatible`).
    #[must_use]
    pub const fn provider(&self) -> ColdProviderKind {
        self.provider
    }

    /// Returns the pinned socket address (no DNS resolution).
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Returns the explicit HTTP `Host` header value.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Returns the bucket name.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Returns the signing region (e.g., `"us-east-1"`, `"auto"`, `"us-west-004"`).
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// Returns the canonical SHA-256 endpoint approval identity digest.
    #[must_use]
    pub const fn endpoint_digest(&self) -> ContentDigest {
        self.endpoint_digest
    }

    /// Returns the independent operator approval digest.
    #[must_use]
    pub const fn endpoint_approval(&self) -> ContentDigest {
        self.endpoint_approval
    }
}

impl fmt::Debug for ColdS3Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ColdS3Endpoint")
            .field("provider", &self.provider)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("endpoint_digest", &self.endpoint_digest)
            .finish()
    }
}

/// Scope-bound S3/R2/B2 credentials wrapped in [`Zeroizing`] / [`SecretBytes`].
///
/// Unconditionally prints `"[REDACTED]"` in `Debug` and `Display`.
pub struct ColdS3Credentials {
    access_key_id: Zeroizing<String>,
    secret_access_key: SecretBytes,
    session_token: Option<SecretBytes>,
    scope: SecretScope,
}

impl ColdS3Credentials {
    /// Constructs validated credentials explicitly bound to an `AdapterFamily::ArchiveS3` scope.
    pub fn new(
        access_key_id: &str,
        secret_access_key: SecretBytes,
        session_token: Option<SecretBytes>,
        scope: SecretScope,
    ) -> Result<Self, PackError> {
        if scope.adapter_family() != AdapterFamily::ArchiveS3 {
            return Err(PackError::CryptoAuthority {
                detail: format!(
                    "ColdS3Credentials requires AdapterFamily::ArchiveS3, got {}",
                    scope.adapter_family()
                ),
            });
        }
        if access_key_id.is_empty()
            || access_key_id.len() > 128
            || !access_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(PackError::InvalidConfig {
                detail: "invalid S3 access key identifier format".to_owned(),
            });
        }
        if secret_access_key.len() > 256
            || !secret_access_key
                .as_slice()
                .iter()
                .all(|&b| (33..=126).contains(&b))
        {
            return Err(PackError::InvalidConfig {
                detail: "invalid S3 secret access key format".to_owned(),
            });
        }
        if let Some(tok) = &session_token
            && (tok.len() > 4096 || !tok.as_slice().iter().all(|&b| (33..=126).contains(&b)))
        {
            return Err(PackError::InvalidConfig {
                detail: "invalid S3 session token format".to_owned(),
            });
        }
        Ok(Self {
            access_key_id: Zeroizing::new(access_key_id.to_owned()),
            secret_access_key,
            session_token,
            scope,
        })
    }

    /// Loads the S3 secret access key from an explicit [`SecretStore`] under caller [`SecretAccessCx`].
    pub fn from_vault(
        store: &dyn SecretStore,
        cx: &SecretAccessCx,
        access_key_id: &str,
        secret_id: &SecretId,
        session_token: Option<SecretBytes>,
    ) -> Result<Self, PackError> {
        if cx.scope().adapter_family() != AdapterFamily::ArchiveS3 {
            return Err(PackError::CryptoAuthority {
                detail: format!(
                    "SecretAccessCx for S3 requires AdapterFamily::ArchiveS3, got {}",
                    cx.scope().adapter_family()
                ),
            });
        }
        cx.authorize(SecretOperation::Read, Some(secret_id), None)?;
        let (handle, secret) = store.fetch(cx, secret_id)?.into_parts();
        Self::new(access_key_id, secret, session_token, handle.scope)
    }

    /// Returns the bound [`SecretScope`].
    #[must_use]
    pub const fn scope(&self) -> &SecretScope {
        &self.scope
    }

    pub(super) fn access_key_id(&self) -> &str {
        self.access_key_id.as_str()
    }

    pub(super) fn secret_access_key(&self) -> &SecretBytes {
        &self.secret_access_key
    }

    pub(super) fn session_token(&self) -> Option<&SecretBytes> {
        self.session_token.as_ref()
    }
}

impl fmt::Debug for ColdS3Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ColdS3Credentials({REDACTED_SECRET_DISPLAY})")
    }
}

impl fmt::Display for ColdS3Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ColdS3Credentials({REDACTED_SECRET_DISPLAY})")
    }
}

/// Hard resource and timeout bounds for [`S3CompatiblePackTransport`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColdS3Limits {
    /// Maximum HTTP response head length in bytes (default `32 KiB`).
    pub max_header_bytes: usize,
    /// Maximum HTTP response body length in bytes (default `256 MiB`).
    pub max_response_bytes: usize,
    /// TCP connect timeout in milliseconds (default `5_000 ms`).
    pub connect_timeout_ms: u64,
    /// Socket read/write timeout in milliseconds (default `30_000 ms`).
    pub io_timeout_ms: u64,
}

impl Default for ColdS3Limits {
    fn default() -> Self {
        Self {
            max_header_bytes: 32 * 1024,
            max_response_bytes: 256 * 1024 * 1024,
            connect_timeout_ms: 5_000,
            io_timeout_ms: 30_000,
        }
    }
}

/// Verified upload receipt returned by [`ColdPackTransport::put_object`] or multipart upload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdPutReceipt {
    /// Uploaded opaque object key.
    pub object_key: String,
    /// Remote provider ETag returned on completion.
    pub etag: String,
    /// Total ciphertext bytes uploaded.
    pub bytes_uploaded: u64,
    /// Number of parts uploaded (`1` for single PUT).
    pub part_count: u32,
    /// SHA-256 of the complete uploaded payload.
    pub content_sha256: ContentDigest,
}

/// Verified partial-content response returned by [`ColdPackTransport::get_object_range`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdRangeResponse {
    /// Requested object key.
    pub object_key: String,
    /// Inclusive start byte offset requested.
    pub start_inclusive: u64,
    /// Inclusive end byte offset requested.
    pub end_inclusive: u64,
    /// Remote provider ETag returned with the range response.
    pub etag: String,
    /// Exact downloaded range bytes.
    pub body: Vec<u8>,
}

/// Verified full-object response returned by [`ColdPackTransport::get_object`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdGetResponse {
    /// Requested object key.
    pub object_key: String,
    /// Remote provider ETag returned with the object.
    pub etag: String,
    /// Downloaded object bytes.
    pub body: Vec<u8>,
}

/// Explicit cold-tier S3/R2/B2 object transport boundary.
pub trait ColdPackTransport {
    /// Returns the canonical SHA-256 identity of the bound endpoint.
    fn endpoint_digest(&self) -> ContentDigest;

    /// Uploads one complete object via signed HTTP `PUT`.
    fn put_object(
        &mut self,
        object_key: &str,
        body: &[u8],
        content_sha256: ContentDigest,
        now_ns: TimestampNs,
    ) -> Result<ColdPutReceipt, PackError>;

    /// Uploads a large object via S3 multipart (`POST ?uploads=`, `PUT ?partNumber=`, `POST ?uploadId=`).
    fn put_object_multipart(
        &mut self,
        object_key: &str,
        body: &[u8],
        part_size: usize,
        now_ns: TimestampNs,
    ) -> Result<ColdPutReceipt, PackError>;

    /// Performs a bounded signed HTTP `GET` with `Range: bytes=start-end` (requires HTTP `206`).
    fn get_object_range(
        &mut self,
        object_key: &str,
        start_inclusive: u64,
        end_inclusive: u64,
        now_ns: TimestampNs,
    ) -> Result<ColdRangeResponse, PackError>;

    /// Performs a bounded signed HTTP `GET` for the complete object (requires HTTP `200`).
    fn get_object(
        &mut self,
        object_key: &str,
        max_bytes: usize,
        now_ns: TimestampNs,
    ) -> Result<ColdGetResponse, PackError>;
}

/// Pure-Rust HTTP/1.1 + AWS SigV4 cold-tier S3 / Cloudflare R2 / Backblaze B2 transport.
pub struct S3CompatiblePackTransport {
    endpoint: ColdS3Endpoint,
    credentials: ColdS3Credentials,
    limits: ColdS3Limits,
}

impl S3CompatiblePackTransport {
    /// Creates a new transport bound to an approved [`ColdS3Endpoint`] and [`ColdS3Credentials`].
    pub fn new(
        endpoint: ColdS3Endpoint,
        credentials: ColdS3Credentials,
        limits: ColdS3Limits,
    ) -> Result<Self, PackError> {
        if limits.max_header_bytes < 1024
            || limits.max_response_bytes == 0
            || limits.connect_timeout_ms == 0
            || limits.io_timeout_ms == 0
        {
            return Err(PackError::InvalidConfig {
                detail: "invalid ColdS3Limits bounds".to_owned(),
            });
        }
        Ok(Self {
            endpoint,
            credentials,
            limits,
        })
    }

    /// Returns the bound [`ColdS3Endpoint`].
    #[must_use]
    pub const fn endpoint(&self) -> &ColdS3Endpoint {
        &self.endpoint
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_signed(
        &self,
        method: &str,
        object_key: &str,
        query: &str,
        extra_headers: &[(&'static str, String)],
        body: &[u8],
        payload_digest: ContentDigest,
        now_ns: TimestampNs,
        max_response_bytes: usize,
    ) -> Result<HttpReply, PackError> {
        validate_object_key(object_key)?;
        let req_head = build_sigv4_request_head(
            &self.endpoint,
            &self.credentials,
            now_ns,
            method,
            object_key,
            query,
            extra_headers,
            payload_digest,
            body.len(),
            self.limits.max_header_bytes,
        )?;

        let connect_timeout = Duration::from_millis(self.limits.connect_timeout_ms);
        let io_timeout = Duration::from_millis(self.limits.io_timeout_ms);
        let mut stream =
            TcpStream::connect_timeout(&self.endpoint.peer, connect_timeout).map_err(|_| {
                PackError::ArchiveTransport {
                    detail: "TCP connect to cold S3 endpoint failed".to_owned(),
                }
            })?;
        stream
            .set_write_timeout(Some(io_timeout))
            .map_err(|_| PackError::ArchiveTransport {
                detail: "failed to configure socket write timeout".to_owned(),
            })?;
        stream
            .set_read_timeout(Some(io_timeout))
            .map_err(|_| PackError::ArchiveTransport {
                detail: "failed to configure socket read timeout".to_owned(),
            })?;

        write_socket_all(&mut stream, &req_head)?;
        if !body.is_empty() {
            write_socket_all(&mut stream, body)?;
        }

        let effective_max = max_response_bytes.min(self.limits.max_response_bytes);
        read_http1_response(&mut stream, self.limits.max_header_bytes, effective_max)
    }

    fn abort_multipart_best_effort(&self, object_key: &str, upload_id: &str, now_ns: TimestampNs) {
        let query = canonical_query(&[("uploadId", upload_id)]);
        let _ = self.execute_signed(
            "DELETE",
            object_key,
            &query,
            &[],
            b"",
            ContentDigest::sha256(b""),
            now_ns,
            16 * 1024,
        );
    }
}

impl fmt::Debug for S3CompatiblePackTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S3CompatiblePackTransport")
            .field("endpoint", &self.endpoint)
            .field("credentials", &REDACTED_SECRET_DISPLAY)
            .finish()
    }
}

impl ColdPackTransport for S3CompatiblePackTransport {
    fn endpoint_digest(&self) -> ContentDigest {
        self.endpoint.endpoint_digest
    }

    fn put_object(
        &mut self,
        object_key: &str,
        body: &[u8],
        content_sha256: ContentDigest,
        now_ns: TimestampNs,
    ) -> Result<ColdPutReceipt, PackError> {
        let actual_sha = ContentDigest::sha256(body);
        if actual_sha != content_sha256 {
            return Err(PackError::DigestMismatch {
                expected: content_sha256,
                actual: actual_sha,
            });
        }
        let checksum_b64 = encode_base64(&content_sha256.bytes());
        let reply = self.execute_signed(
            "PUT",
            object_key,
            "",
            &[
                ("content-type", "application/octet-stream".to_owned()),
                ("x-amz-checksum-sha256", checksum_b64),
            ],
            body,
            content_sha256,
            now_ns,
            64 * 1024,
        )?;
        if reply.status != 200 {
            return Err(PackError::ArchiveTransport {
                detail: format!("S3 PUT rejected with HTTP status {}", reply.status),
            });
        }
        let etag = reply.unique_header("etag")?.to_owned();
        if etag.is_empty() || etag.len() > 1024 {
            return Err(PackError::ArchiveTransport {
                detail: "S3 PUT response missing valid ETag".to_owned(),
            });
        }
        Ok(ColdPutReceipt {
            object_key: object_key.to_owned(),
            etag,
            bytes_uploaded: body.len() as u64,
            part_count: 1,
            content_sha256,
        })
    }

    fn put_object_multipart(
        &mut self,
        object_key: &str,
        body: &[u8],
        part_size: usize,
        now_ns: TimestampNs,
    ) -> Result<ColdPutReceipt, PackError> {
        if part_size == 0 || body.is_empty() {
            return Err(PackError::InvalidConfig {
                detail: "multipart upload requires non-empty body and part_size >= 1".to_owned(),
            });
        }
        let part_count_usize = body.len().div_ceil(part_size);
        if part_count_usize > 10_000 {
            return Err(PackError::InvalidConfig {
                detail: format!("multipart part count {part_count_usize} exceeds S3 limit 10000"),
            });
        }
        let whole_sha = ContentDigest::sha256(body);

        let init_reply = self.execute_signed(
            "POST",
            object_key,
            "uploads=",
            &[("x-amz-checksum-algorithm", "SHA256".to_owned())],
            b"",
            ContentDigest::sha256(b""),
            now_ns,
            64 * 1024,
        )?;
        if init_reply.status != 200 {
            return Err(PackError::ArchiveTransport {
                detail: format!(
                    "InitiateMultipartUpload rejected with HTTP status {}",
                    init_reply.status
                ),
            });
        }
        let init_fields = parse_flat_s3_xml(&init_reply.body, "InitiateMultipartUploadResult")?;
        let upload_id = init_fields
            .get("UploadId")
            .filter(|id| !id.is_empty() && id.len() <= 1024 && !id.chars().any(char::is_control))
            .ok_or_else(|| PackError::ArchiveTransport {
                detail: "InitiateMultipartUploadResult missing valid UploadId".to_owned(),
            })?
            .clone();

        let mut completed_parts: Vec<(u32, String, ContentDigest)> =
            Vec::with_capacity(part_count_usize);
        for (idx, chunk) in body.chunks(part_size).enumerate() {
            let part_number = u32::try_from(idx + 1).map_err(|_| PackError::ArithmeticOverflow)?;
            let part_sha = ContentDigest::sha256(chunk);
            let checksum_b64 = encode_base64(&part_sha.bytes());
            let part_num_str = part_number.to_string();
            let query = canonical_query(&[("partNumber", &part_num_str), ("uploadId", &upload_id)]);
            let part_res = self.execute_signed(
                "PUT",
                object_key,
                &query,
                &[("x-amz-checksum-sha256", checksum_b64)],
                chunk,
                part_sha,
                now_ns,
                64 * 1024,
            );
            let reply = match part_res {
                Ok(r) if r.status == 200 => r,
                Ok(r) => {
                    self.abort_multipart_best_effort(object_key, &upload_id, now_ns);
                    return Err(PackError::ArchiveTransport {
                        detail: format!(
                            "UploadPart {part_number} rejected with HTTP status {}",
                            r.status
                        ),
                    });
                }
                Err(err) => {
                    self.abort_multipart_best_effort(object_key, &upload_id, now_ns);
                    return Err(err);
                }
            };
            let etag = match reply.unique_header("etag") {
                Ok(e) if !e.is_empty() && e.len() <= 1024 => e.to_owned(),
                _ => {
                    self.abort_multipart_best_effort(object_key, &upload_id, now_ns);
                    return Err(PackError::ArchiveTransport {
                        detail: format!("UploadPart {part_number} missing valid ETag"),
                    });
                }
            };
            completed_parts.push((part_number, etag, part_sha));
        }

        let complete_xml = build_complete_multipart_xml(&completed_parts)?;
        let complete_sha = ContentDigest::sha256(&complete_xml);
        let complete_query = canonical_query(&[("uploadId", &upload_id)]);
        let complete_reply = self.execute_signed(
            "POST",
            object_key,
            &complete_query,
            &[("content-type", "application/xml".to_owned())],
            &complete_xml,
            complete_sha,
            now_ns,
            64 * 1024,
        )?;
        if complete_reply.status != 200 {
            return Err(PackError::ArchiveTransport {
                detail: format!(
                    "CompleteMultipartUpload rejected with HTTP status {}",
                    complete_reply.status
                ),
            });
        }
        let complete_fields =
            parse_flat_s3_xml(&complete_reply.body, "CompleteMultipartUploadResult")?;
        let final_etag = complete_fields
            .get("ETag")
            .filter(|e| !e.is_empty() && e.len() <= 1024)
            .ok_or_else(|| PackError::ArchiveTransport {
                detail: "CompleteMultipartUploadResult missing valid ETag".to_owned(),
            })?
            .clone();

        Ok(ColdPutReceipt {
            object_key: object_key.to_owned(),
            etag: final_etag,
            bytes_uploaded: body.len() as u64,
            part_count: u32::try_from(completed_parts.len())
                .map_err(|_| PackError::ArithmeticOverflow)?,
            content_sha256: whole_sha,
        })
    }

    fn get_object_range(
        &mut self,
        object_key: &str,
        start_inclusive: u64,
        end_inclusive: u64,
        now_ns: TimestampNs,
    ) -> Result<ColdRangeResponse, PackError> {
        if end_inclusive < start_inclusive {
            return Err(PackError::InvalidConfig {
                detail: "Range end_inclusive must be >= start_inclusive".to_owned(),
            });
        }
        let expected_len_u64 = end_inclusive
            .checked_sub(start_inclusive)
            .and_then(|d| d.checked_add(1))
            .ok_or(PackError::ArithmeticOverflow)?;
        let expected_len =
            usize::try_from(expected_len_u64).map_err(|_| PackError::ArithmeticOverflow)?;
        let range_header = format!("bytes={start_inclusive}-{end_inclusive}");
        let reply = self.execute_signed(
            "GET",
            object_key,
            "",
            &[("range", range_header)],
            b"",
            ContentDigest::sha256(b""),
            now_ns,
            expected_len.saturating_add(1024),
        )?;
        if reply.status == 404 {
            return Err(PackError::ArchiveMissing {
                object_key: object_key.to_owned(),
            });
        }
        if reply.status != 206 {
            return Err(PackError::ArchiveTransport {
                detail: format!("Range-GET expected HTTP 206, received {}", reply.status),
            });
        }
        if reply.body.len() != expected_len {
            return Err(PackError::ArchiveIntegrity {
                detail: format!(
                    "Range-GET returned {} bytes, expected {expected_len}",
                    reply.body.len()
                ),
            });
        }
        let etag = reply.unique_header("etag")?.to_owned();
        Ok(ColdRangeResponse {
            object_key: object_key.to_owned(),
            start_inclusive,
            end_inclusive,
            etag,
            body: reply.body,
        })
    }

    fn get_object(
        &mut self,
        object_key: &str,
        max_bytes: usize,
        now_ns: TimestampNs,
    ) -> Result<ColdGetResponse, PackError> {
        let reply = self.execute_signed(
            "GET",
            object_key,
            "",
            &[],
            b"",
            ContentDigest::sha256(b""),
            now_ns,
            max_bytes,
        )?;
        if reply.status == 404 {
            return Err(PackError::ArchiveMissing {
                object_key: object_key.to_owned(),
            });
        }
        if reply.status != 200 {
            return Err(PackError::ArchiveTransport {
                detail: format!("S3 GET expected HTTP 200, received {}", reply.status),
            });
        }
        let etag = reply.unique_header("etag")?.to_owned();
        Ok(ColdGetResponse {
            object_key: object_key.to_owned(),
            etag,
            body: reply.body,
        })
    }
}
