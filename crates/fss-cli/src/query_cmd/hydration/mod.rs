#![forbid(unsafe_code)]
//! Privacy-masked H2 (structured analytic) and H3 (redacted visual keyframe/crop) hydration.
//!
//! All capabilities and launcher grants fail closed before reading source media or decoding
//! pixels. H2 returns bounded, anchor-pinned structured projections (tracks, boxes, model
//! receipts, failure-domain clusters, certified graph neighborhood). H3 enforces the sensor's
//! active privacy-mask policy (`transform:bounding_box_redact`) directly on the decoded buffer
//! BEFORE cropping, downscaling, or pure-Rust JPEG encoding.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, EventId, OperationId,
    PrincipalId, RootAuthoritySpec, SessionId,
};
use fss_reference::agent_orient::OrientLimits;
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::{SESSION_JOURNAL_FILE, SESSIONS_RELPATH};
use fss_reference::retained_source::{ImmutableRetainedReadLimits, ImmutableRetainedSource};
use fss_reference::{ADP_REPLAY_ROW_ID, ReplayCx};

use crate::error::ExitIdentity;
use crate::json_output::object;

mod base64;
/// Payload-proportional token, byte, and storage-operation budget pricing for H0..=H3.
pub mod budget;
mod envelope;
/// H2 structured analytic hydration (tracks, model receipts, failure-domain clusters, graph).
pub mod h2;
mod h2_provenance;
/// H3 privacy-masked visual keyframe and crop hydration with mandatory pre-encode redaction.
pub mod h3;
mod h3_media;
mod render_json;

pub use base64::{decode_base64, encode_base64};

#[cfg(test)]
mod tests;

/// Required capability for H2 structured analytic hydration.
pub const CAP_AGENT_HYDRATE_H2: &str = "CAP-AGENT-HYDRATE-H2-001";
/// Required capability for H3 privacy-masked visual keyframe/crop hydration.
pub const CAP_AGENT_HYDRATE_H3: &str = "CAP-AGENT-HYDRATE-H3-001";
/// Fail-closed error identity for missing capability or missing visual launcher grant.
pub const ERR_CAPABILITY_DENIED: &str = "ERR-CAPABILITY-DENIED-001";
/// Fail-closed error identity for violated H2/H3 structural or visual resource bounds.
pub const ERR_HYDRATION_BOUNDS: &str = "ERR-HYDRATION-BOUNDS-001";
/// Canonical digest domain for `H2HydrationReceipt`.
pub const H2_RECEIPT_DOMAIN: &str = "fss.hydration.h2_receipt.v1";
/// Canonical digest domain for `H3FrameReceipt` and aggregate H3 visual receipts.
pub const H3_RECEIPT_DOMAIN: &str = "fss.hydration.h3_receipt.v1";
/// Registered response payload schema for H2 analytic hydration projections.
pub const H2_PAYLOAD_SCHEMA: &str = "fss.agent_hydration_h2.v1";
/// Registered response payload schema for H3 visual keyframe/crop hydration projections.
pub const H3_PAYLOAD_SCHEMA: &str = "fss.agent_hydration_h3.v1";

/// Minimum number of frames admitted by an H3 visual hydration request.
pub const MIN_H3_FRAMES: usize = 1;
/// Hard ceiling on frames returned by one H3 visual hydration request.
pub const MAX_H3_FRAMES: usize = 4;
/// Default and ceiling byte limit across all encoded JPEGs in one H3 response (512 KiB).
pub const DEFAULT_MAX_H3_BYTES: usize = 512 * 1024;
/// Minimum admitted output max-dimension in pixels for H3 visual frames.
pub const MIN_H3_DIMENSION: u32 = 64;
/// Default output max-dimension in pixels for H3 visual frames.
pub const DEFAULT_H3_DIMENSION: u32 = 640;
/// Hard ceiling on output max-dimension in pixels for H3 visual frames.
pub const MAX_H3_DIMENSION: u32 = 1280;
/// Default JPEG quality factor for H3 visual derivatives.
pub const DEFAULT_H3_JPEG_QUALITY: u8 = 80;
/// Maximum complete serialized envelope bytes for an H2 response (256 KiB).
pub const MAX_H2_OUTPUT_BYTES: usize = 256 * 1024;
/// Maximum complete serialized envelope bytes for an H3 response (1 MiB).
pub const MAX_H3_OUTPUT_BYTES: usize = 1024 * 1024;
/// Maximum retained source read bytes for bounded H2/H3 hydration reads (128 MiB).
pub(crate) const MAX_HYDRATION_READ_BYTES: usize = 128 * 1024 * 1024;
/// Maximum retained source read attempts for bounded H2/H3 hydration reads.
pub(crate) const MAX_HYDRATION_READ_OBJECTS: usize = 65_536;

/// Explicit axis-aligned crop rectangle (`X,Y,W,H`) validated inside decoded frame bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CropBox {
    /// Left origin in decoded source pixels.
    pub x: u32,
    /// Top origin in decoded source pixels.
    pub y: u32,
    /// Non-zero crop width in decoded source pixels.
    pub width: u32,
    /// Non-zero crop height in decoded source pixels.
    pub height: u32,
}

impl CropBox {
    /// Parses a strict canonical `X,Y,W,H` decimal crop box specification.
    pub fn parse(raw: &str) -> Result<Self, HydrationError> {
        let parts: Vec<&str> = raw.split(',').collect();
        if parts.len() != 4 {
            return Err(HydrationError::InvalidRequest(
                "crop_box must be four comma-separated canonical u32 decimals: X,Y,W,H".to_owned(),
            ));
        }
        let mut vals = [0_u32; 4];
        for (slot, part) in vals.iter_mut().zip(parts.iter()) {
            let parsed = part.parse::<u32>().map_err(|_| {
                HydrationError::InvalidRequest("crop_box coordinate must be a u32 integer".into())
            })?;
            if parsed.to_string() != *part {
                return Err(HydrationError::InvalidRequest(
                    "crop_box coordinates must use canonical decimal spelling".into(),
                ));
            }
            *slot = parsed;
        }
        if vals[2] == 0 || vals[3] == 0 {
            return Err(HydrationError::BoundsExceeded(
                "crop_box width and height must both be positive".into(),
            ));
        }
        Ok(Self {
            x: vals[0],
            y: vals[1],
            width: vals[2],
            height: vals[3],
        })
    }

    /// Validates that this crop box lies strictly inside `[frame_width, frame_height]`.
    pub fn validate_within(&self, dimensions: [u32; 2]) -> Result<(), HydrationError> {
        if self.width == 0 || self.height == 0 {
            return Err(HydrationError::BoundsExceeded(
                "crop_box width and height must be nonzero".into(),
            ));
        }
        let end_x = u64::from(self.x).checked_add(u64::from(self.width));
        let end_y = u64::from(self.y).checked_add(u64::from(self.height));
        if end_x.is_none_or(|x| x > u64::from(dimensions[0]))
            || end_y.is_none_or(|y| y > u64::from(dimensions[1]))
        {
            return Err(HydrationError::BoundsExceeded(format!(
                "crop_box {},{},{},{} exceeds decoded frame bounds {}x{}",
                self.x, self.y, self.width, self.height, dimensions[0], dimensions[1]
            )));
        }
        Ok(())
    }

    /// Renders this crop box as canonical JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        object(&[
            ("x", self.x.to_string()),
            ("y", self.y.to_string()),
            ("width", self.width.to_string()),
            ("height", self.height.to_string()),
        ])
    }
}

/// Hard visual bounds enforced before decoding or returning any H3 frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct H3Limits {
    /// Maximum frames returned in one H3 call (`1..=4`).
    pub max_h3_frames: usize,
    /// Maximum total encoded JPEG bytes across all frames (default and ceiling `512 KiB`).
    pub max_h3_bytes: usize,
    /// Maximum output pixel dimension on either axis (`64..=1280`, default `640`).
    pub max_dimension: u32,
}

impl Default for H3Limits {
    fn default() -> Self {
        Self {
            max_h3_frames: MAX_H3_FRAMES,
            max_h3_bytes: DEFAULT_MAX_H3_BYTES,
            max_dimension: DEFAULT_H3_DIMENSION,
        }
    }
}

impl H3Limits {
    /// Validates every H3 visual bound fail-closed before reading media.
    pub fn validate(&self) -> Result<(), HydrationError> {
        if !(MIN_H3_FRAMES..=MAX_H3_FRAMES).contains(&self.max_h3_frames) {
            return Err(HydrationError::BoundsExceeded(format!(
                "max_h3_frames must be in {MIN_H3_FRAMES}..={MAX_H3_FRAMES}, got {}",
                self.max_h3_frames
            )));
        }
        if !(1..=DEFAULT_MAX_H3_BYTES).contains(&self.max_h3_bytes) {
            return Err(HydrationError::BoundsExceeded(format!(
                "max_h3_bytes must be in 1..={DEFAULT_MAX_H3_BYTES}, got {}",
                self.max_h3_bytes
            )));
        }
        if !(MIN_H3_DIMENSION..=MAX_H3_DIMENSION).contains(&self.max_dimension) {
            return Err(HydrationError::BoundsExceeded(format!(
                "max_dimension must be in {MIN_H3_DIMENSION}..={MAX_H3_DIMENSION}, got {}",
                self.max_dimension
            )));
        }
        Ok(())
    }
}

/// Exact immutable subject selected for H2 or H3 hydration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HydrationTarget {
    /// Exact committed event revision.
    Event {
        /// Stable event identity.
        event_id: EventId,
        /// Exact canonical revision digest.
        revision_digest: ContentDigest,
    },
    /// Exact completed retained file import.
    Import {
        /// Exact import identity digest.
        import_id: ContentDigest,
    },
}

/// Explicit capability and launcher grants evaluated before any data access.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CapabilityGrantContext {
    /// Explicit request/operator capability grants (never inferred from transport presence).
    pub granted_capabilities: BTreeSet<String>,
    /// Explicit launcher-only visual hydration flag (`--allow-visual-hydration`).
    pub allow_visual_hydration: bool,
}

impl CapabilityGrantContext {
    /// Verifies that `CAP-AGENT-HYDRATE-H2-001` is granted; fails closed otherwise.
    pub fn require_h2(&self, effective: &BTreeSet<String>) -> Result<(), HydrationError> {
        if !effective.contains(CAP_AGENT_HYDRATE_H2) {
            return Err(HydrationError::CapabilityDenied(format!(
                "H2 analytic hydration requires explicit capability {CAP_AGENT_HYDRATE_H2}"
            )));
        }
        Ok(())
    }

    /// Dual fail-closed gate for H3 visual hydration: requires BOTH `--allow-visual-hydration`
    /// AND `CAP-AGENT-HYDRATE-H3-001`. Decodes zero pixels if either gate is absent.
    pub fn require_h3(&self, effective: &BTreeSet<String>) -> Result<(), HydrationError> {
        if !self.allow_visual_hydration {
            return Err(HydrationError::CapabilityDenied(
                "H3 visual hydration requires explicit --allow-visual-hydration launcher grant"
                    .to_owned(),
            ));
        }
        if !effective.contains(CAP_AGENT_HYDRATE_H3) {
            return Err(HydrationError::CapabilityDenied(format!(
                "H3 visual hydration requires explicit capability {CAP_AGENT_HYDRATE_H3}"
            )));
        }
        Ok(())
    }
}

/// Extended H2 or H3 CLI/MCP hydration dispatch request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExtendedHydrationRequest {
    /// H2 structured analytic hydration request.
    H2(h2::H2HydrationRequest),
    /// H3 privacy-masked visual hydration request.
    H3(h3::H3HydrationRequest),
}

/// Typed fail-closed refusal for H2/H3 hydration. Never carries raw pixel or secret bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HydrationError {
    /// Missing required capability or missing `--allow-visual-hydration` launcher grant.
    CapabilityDenied(String),
    /// Caller violated a hard visual, frame, byte, crop, or token bound.
    BoundsExceeded(String),
    /// Malformed or incomplete request parameters.
    InvalidRequest(String),
    /// Deployment head moved relative to the pinned anchor.
    AnchorMismatch(String),
    /// Requested event revision, import, or segment was not found.
    NotFound(String),
    /// Privacy-mask resolution or enforcement refused unmasked access.
    PrivacyRefused {
        /// Registered privacy error identity.
        error_id: &'static str,
        /// Safe non-disclosing reason.
        detail: String,
    },
    /// Target evidence is covered by a committed deletion record.
    EvidenceDeleted(String),
    /// Pure-Rust codec decode or encode refused the frame.
    CodecFailure(String),
    /// Custody or session verification failed.
    CustodyFailure(String),
    /// Cooperative cancellation was observed before completion.
    Cancelled,
}

impl HydrationError {
    /// Registered stable machine error identity for this refusal.
    #[must_use]
    pub const fn error_id(&self) -> &'static str {
        match self {
            Self::CapabilityDenied(_) => ERR_CAPABILITY_DENIED,
            Self::BoundsExceeded(_) => ERR_HYDRATION_BOUNDS,
            Self::InvalidRequest(_) => crate::error::ERR_CLI_MALFORMED_VALUE,
            Self::AnchorMismatch(_) => "ERR-AGENT-RESNAPSHOT-001",
            Self::NotFound(_) => crate::orient_cmd::ERR_AGENT_EVENT_NOT_FOUND,
            Self::PrivacyRefused { error_id, .. } => error_id,
            Self::EvidenceDeleted(_) => "ERR-EVIDENCE-DELETED-001",
            Self::CodecFailure(_) => "ERR-DECODE-001",
            Self::CustodyFailure(_) | Self::Cancelled => {
                crate::orient_cmd::ERR_AGENT_CONTEXT_INCOMPLETE
            }
        }
    }
}

impl fmt::Display for HydrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityDenied(detail)
            | Self::BoundsExceeded(detail)
            | Self::InvalidRequest(detail)
            | Self::AnchorMismatch(detail)
            | Self::NotFound(detail)
            | Self::EvidenceDeleted(detail)
            | Self::CodecFailure(detail)
            | Self::CustodyFailure(detail) => f.write_str(detail),
            Self::PrivacyRefused { detail, .. } => f.write_str(detail),
            Self::Cancelled => f.write_str("hydration cancelled before release"),
        }
    }
}

impl std::error::Error for HydrationError {}

/// Resolves effective capabilities by merging explicit operator grants with optional retained
/// session capabilities verified read-only from `<root>/agent/sessions/journal.fssj`.
pub(crate) fn resolve_effective_capabilities(
    root: &Path,
    principal: &PrincipalId,
    session_id: Option<&SessionId>,
    expected_generation: Option<u64>,
    explicit: &BTreeSet<String>,
) -> Result<BTreeSet<String>, HydrationError> {
    let mut effective = explicit.clone();
    if let Some(session_id) = session_id {
        let journal_path = root.join(SESSIONS_RELPATH).join(SESSION_JOURNAL_FILE);
        let bytes = fs::read(&journal_path).map_err(|_| {
            HydrationError::CustodyFailure(
                "retained session journal is unavailable for capability resolution".into(),
            )
        })?;
        let state = inspect_session_bytes(
            &bytes,
            DurableSessionLimits::default(),
            WorkClaimLimits::default(),
        )
        .map_err(|_| {
            HydrationError::CustodyFailure("retained session journal failed verification".into())
        })?;
        let entry = state
            .sessions
            .iter()
            .find(|entry| {
                entry.session.session_id == *session_id && entry.session.principal_id == *principal
            })
            .ok_or_else(|| {
                HydrationError::CapabilityDenied(
                    "session is unknown or not owned by the requesting principal".into(),
                )
            })?;
        if let Some(generation) = expected_generation
            && entry.session.symbol_table_generation != generation
        {
            return Err(HydrationError::AnchorMismatch(
                "session symbol_table_generation mismatch".into(),
            ));
        }
        effective.extend(entry.session.capabilities.iter().cloned());
    }
    Ok(effective)
}

/// Builds a bounded read-only `ReplayCx` over `root`.
pub(crate) fn build_readonly_cx(
    root: &Path,
    principal: &PrincipalId,
    capabilities: &BTreeSet<String>,
) -> Result<ReplayCx, HydrationError> {
    let mut caps: Vec<String> = capabilities.iter().cloned().collect();
    if !caps.iter().any(|c| c == ADP_REPLAY_ROW_ID) {
        caps.push(ADP_REPLAY_ROW_ID.to_owned());
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:hydration-h2-h3".to_owned(),
        operation_id: OperationId::parse("operation:hydration-h2-h3")
            .map_err(|_| HydrationError::InvalidRequest("invalid hydration operation id".into()))?,
        principal: principal.as_str().to_owned(),
        capabilities: caps,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(MAX_HYDRATION_READ_BYTES as u64)
            .storage_operations(MAX_HYDRATION_READ_OBJECTS as u64)
            .build()
            .map_err(|_| HydrationError::BoundsExceeded("invalid hydration read budget".into()))?,
        privacy_scope: "private:property".to_owned(),
        retention_scope: "retention:current-deletion-restrictions".to_owned(),
        anchor_universe: ContentDigest::sha256(b"fss.hydration.readonly"),
        generation: 1,
    })
    .map_err(|_| HydrationError::InvalidRequest("invalid hydration context authority".into()))?;
    ReplayCx::from_context_authority_read_only(&authority, root.to_path_buf()).map_err(|_| {
        HydrationError::CustodyFailure("could not open read-only replay context".into())
    })
}

/// Opens a bounded read-only `ImmutableRetainedSource` borrowing `cx` and `cancelled`.
pub(crate) fn open_readonly_source<'a>(
    root: &Path,
    cx: &'a ReplayCx,
    cancelled: &'a (dyn Fn() -> bool + Sync),
) -> Result<ImmutableRetainedSource<'a>, HydrationError> {
    if cancelled() {
        return Err(HydrationError::Cancelled);
    }
    ImmutableRetainedSource::open_cancellable(
        root,
        ImmutableRetainedReadLimits {
            snapshot: OrientLimits::default(),
            max_read_bytes: MAX_HYDRATION_READ_BYTES,
            max_read_objects: MAX_HYDRATION_READ_OBJECTS,
        },
        cx,
        cancelled,
    )
    .map_err(|error| HydrationError::CustodyFailure(format!("retained source refused: {error}")))
}

/// Validates that a digest is a canonical nonzero SHA-256 digest.
pub(crate) fn is_valid_sha256(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}

/// Executes an extended H2 or H3 hydration command and renders a registered `AgentResponseEnvelope`.
#[must_use]
pub fn execute_extended(
    request: &ExtendedHydrationRequest,
    control: &crate::RequestControl<'_>,
) -> (String, ExitIdentity) {
    let cancelled = || control.is_cancelled();
    match request {
        ExtendedHydrationRequest::H2(req) => match h2::hydrate_h2(req, &cancelled) {
            Ok(answer) => envelope::render_h2_envelope(req, &answer),
            Err(error) => envelope::render_refusal_envelope(
                &req.root,
                &req.principal,
                req.session_id.as_ref(),
                H2_PAYLOAD_SCHEMA,
                H2_RECEIPT_DOMAIN,
                &error,
            ),
        },
        ExtendedHydrationRequest::H3(req) => match h3::hydrate_h3(req, &cancelled) {
            Ok(answer) => envelope::render_h3_envelope(req, &answer),
            Err(error) => envelope::render_refusal_envelope(
                &req.root,
                &req.principal,
                req.session_id.as_ref(),
                H3_PAYLOAD_SCHEMA,
                H3_RECEIPT_DOMAIN,
                &error,
            ),
        },
    }
}
