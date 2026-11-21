#![forbid(unsafe_code)]
//! Bounded paginated listing and eventual-consistency observation types (FSS-132).
//!
//! Listings never claim completeness when a page is lagging, omits keys, includes stale
//! post-deletion ghosts, or hits the pagination ceiling. Callers inspecting archive state
//! receive explicit consistency diagnostics alongside every page.

use fss_core::ContentDigest;

use crate::multipart::ETag;
use crate::provider::PublicationState;

/// Hard ceiling on keys requested or emitted in a single list page.
pub const MAX_LIST_PAGE_KEYS: usize = 1_024;

/// Hard ceiling on pages fetched by [`ListingCollector`] in one bounded scan.
pub const MAX_LIST_PAGES_PER_COLLECT: usize = 1_024;

/// Maximum UTF-8 bytes allowed in a key or prefix.
pub const MAX_KEY_BYTES: usize = 1_024;

/// Maximum encoded continuation token length.
pub const MAX_CONTINUATION_TOKEN_BYTES: usize = 2_200;

const TOKEN_PREFIX: &str = "fss-list-v1:";

/// Observed consistency status of one returned list page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListingConsistency {
    /// View matched the authoritative state for the scanned window with no injected omissions.
    Consistent,
    /// One or more committed mutations had not yet reached the read/list replica.
    EventualLag {
        /// Number of committed entries not yet visible at `observed_epoch`.
        hidden_entries: usize,
    },
    /// A partial-list fault omitted matching entries from this page.
    PartialOmission {
        /// Number of visible entries omitted from this page.
        omitted_count: usize,
    },
    /// One or more retired/deleted entries lingered as stale ghosts in `LIST`.
    StaleGhostIncluded {
        /// Number of ghost entries included in this page.
        ghost_count: usize,
    },
    /// Page was truncated below caller's `max_keys` and requires continuation.
    TruncatedEarly,
}

impl ListingConsistency {
    /// True only when the page had zero eventual-consistency anomalies.
    #[must_use]
    pub const fn is_consistent(self) -> bool {
        matches!(self, Self::Consistent)
    }

    /// Stable machine-readable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Consistent => "consistent",
            Self::EventualLag { .. } => "eventual_lag",
            Self::PartialOmission { .. } => "partial_omission",
            Self::StaleGhostIncluded { .. } => "stale_ghost_included",
            Self::TruncatedEarly => "truncated_early",
        }
    }
}

/// One object entry returned by `list_objects`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedObject {
    /// Remote object key.
    pub key: String,
    /// Content digest recorded when written.
    pub digest: ContentDigest,
    /// Opaque provider ETag.
    pub etag: ETag,
    /// Payload length in bytes.
    pub size_bytes: u64,
    /// Lattice publication state as seen by the listing index.
    pub state: PublicationState,
    /// Authoritative commit epoch of the indexed revision.
    pub commit_epoch: u64,
    /// Simulator-side diagnostic flag: true when this entry is a post-delete/retire ghost.
    pub is_ghost: bool,
}

/// Bounded request for paginated object or multipart-part listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListRequest {
    /// Optional exact key prefix filter.
    pub prefix: Option<String>,
    /// Opaque continuation token returned by the immediately preceding page.
    pub continuation_token: Option<String>,
    /// Maximum entries requested on this page (`1..=MAX_LIST_PAGE_KEYS`).
    pub max_keys: usize,
}

impl ListRequest {
    /// Creates a bounded first-page listing request.
    #[must_use]
    pub fn first_page(prefix: Option<String>, max_keys: usize) -> Self {
        Self {
            prefix,
            continuation_token: None,
            max_keys,
        }
    }

    /// Validates prefix, token length, and page bounds before execution.
    pub fn validate(&self, max_allowed_keys: usize) -> Result<(), String> {
        let cap = max_allowed_keys.min(MAX_LIST_PAGE_KEYS);
        if self.max_keys == 0 || self.max_keys > cap {
            return Err(format!(
                "max_keys ({}) must be within 1..={cap}",
                self.max_keys
            ));
        }
        if let Some(prefix) = &self.prefix
            && (prefix.len() > MAX_KEY_BYTES || prefix.chars().any(char::is_control))
        {
            return Err("invalid list prefix".to_owned());
        }
        if let Some(token) = &self.continuation_token
            && (token.is_empty()
                || token.len() > MAX_CONTINUATION_TOKEN_BYTES
                || token.chars().any(char::is_control))
        {
            return Err("malformed continuation token".to_owned());
        }
        Ok(())
    }
}

/// One paginated listing response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPage<T> {
    /// Returned entries in canonical lexicographic / part-index order.
    pub entries: Vec<T>,
    /// True when more entries may remain beyond this page.
    pub is_truncated: bool,
    /// Opaque token to pass on the next page request when `is_truncated` is true.
    pub next_continuation_token: Option<String>,
    /// Explicit consistency classification for this page.
    pub consistency: ListingConsistency,
    /// Additional consistency observations when multiple anomalies occurred simultaneously.
    pub anomalies: Vec<ListingConsistency>,
    /// Logical epoch observed by this listing index.
    pub observed_epoch: u64,
    /// Authoritative backend epoch at the instant of the call (simulator telemetry).
    pub authoritative_epoch: u64,
}

/// Aggregate result of scanning all pages of a bounded listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListingCollection<T> {
    /// Collected entries in order.
    pub entries: Vec<T>,
    /// Total pages fetched.
    pub pages_fetched: usize,
    /// True ONLY when pagination terminated cleanly without hitting page caps AND every
    /// page reported [`ListingConsistency::Consistent`]. Never claims complete absence
    /// when eventual lag, omissions, or stale ghosts were observed.
    pub complete: bool,
    /// All non-consistent observations encountered across fetched pages.
    pub consistency_warnings: Vec<ListingConsistency>,
}

/// Encodes a deterministic tamper-evident continuation token binding `(epoch, cursor)`.
pub(crate) fn encode_continuation_token(epoch: u64, cursor: &str) -> String {
    let mut hex = String::with_capacity(cursor.len() * 2);
    for byte in cursor.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    let checksum = token_checksum(epoch, cursor);
    format!("{TOKEN_PREFIX}{epoch:016x}:{checksum}:{hex}")
}

/// Decodes and verifies a continuation token, refusing tampered or malformed inputs.
pub(crate) fn decode_continuation_token(token: &str) -> Result<(u64, String), String> {
    let rest = token
        .strip_prefix(TOKEN_PREFIX)
        .ok_or_else(|| "unknown continuation token prefix".to_owned())?;
    let mut parts = rest.splitn(3, ':');
    let epoch_hex = parts
        .next()
        .ok_or_else(|| "missing continuation epoch".to_owned())?;
    let checksum_hex = parts
        .next()
        .ok_or_else(|| "missing continuation checksum".to_owned())?;
    let cursor_hex = parts
        .next()
        .ok_or_else(|| "missing continuation cursor".to_owned())?;
    if epoch_hex.len() != 16 || checksum_hex.len() != 16 || !cursor_hex.len().is_multiple_of(2) {
        return Err("malformed continuation token fields".to_owned());
    }
    let epoch =
        u64::from_str_radix(epoch_hex, 16).map_err(|_| "invalid continuation epoch".to_owned())?;
    let mut bytes = Vec::with_capacity(cursor_hex.len() / 2);
    for idx in (0..cursor_hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&cursor_hex[idx..idx + 2], 16)
            .map_err(|_| "invalid continuation hex".to_owned())?;
        bytes.push(byte);
    }
    let cursor = String::from_utf8(bytes).map_err(|_| "non-utf8 continuation cursor".to_owned())?;
    if cursor.len() > MAX_KEY_BYTES {
        return Err("continuation cursor exceeds key bound".to_owned());
    }
    if token_checksum(epoch, &cursor) != checksum_hex {
        return Err("continuation token checksum mismatch".to_owned());
    }
    Ok((epoch, cursor))
}

fn token_checksum(epoch: u64, cursor: &str) -> String {
    let mut material = Vec::with_capacity(16 + cursor.len());
    material.extend_from_slice(b"fss-tok-v1:");
    material.extend_from_slice(&epoch.to_be_bytes());
    material.extend_from_slice(cursor.as_bytes());
    let digest = ContentDigest::sha256(&material);
    let b = digest.bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]
    )
}
