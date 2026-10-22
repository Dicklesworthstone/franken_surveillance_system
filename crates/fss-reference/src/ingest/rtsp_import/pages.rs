#![forbid(unsafe_code)]
//! Explicit ordered whole-page selection for one source-closed retained RTSP recording.
//!
//! Page boundaries do not reset sample, byte, native replay or tracking allowances. All selected
//! pages must share one declared source/decode clock and form one adjacent native decode interval.
//! This is a retained-origin profile, not a registered live-device adapter or coverage certificate.

use super::catalog::{self, RtspCatalogImportReceipt, RtspCatalogImportRequest};
use super::*;
use crate::rtsp::recording_catalog::{CatalogScope, MAX_CATALOG_BYTES};
use std::collections::BTreeSet;
use std::ops::Deref;

/// Independent retained-origin profile; single-page request/proof identities remain unchanged.
pub const ADAPTER: &str = "ADP-RTSP-CATALOG-PAGES-001";
pub(crate) const GENERATION: &str = "gen:rtsp-catalog-pages:v1:";
pub(crate) const EVIDENCE: &str =
    "native_rtsp_catalog_pages:continuous_multifragment_mp4:original_rtp_retained";
pub(super) const REQUEST_DOMAIN: &str = "fss.rtsp_catalog_pages_import_request.v1";
pub(super) const PROOF_DOMAIN: &str = "fss.rtsp_catalog_pages_import.v1";
/// Whole-selection page ceiling. Existing whole-import window, sample and byte limits still apply.
pub const MAX_PAGES: usize = 64;

/// Exact immutable page selected by the caller, in native decode order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspCatalogPage {
    /// Explicit durable catalog slot. No latest-pointer or directory discovery is performed.
    pub slot: SlotName,
    /// Independently selected nonzero SHA-256 catalog root.
    pub root: ContentDigest,
}

/// One explicitly pinned selection of complete pages and cumulative reconstruction allowances.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspCatalogPagesImportRequest {
    /// Exact native catalog/recording verifier; no codec fallback.
    pub codec: RtspImportCodec,
    /// One to 64 whole pages, in exact decode order, without repeated roots or slots.
    pub pages: Vec<RtspCatalogPage>,
    /// Common sensor, stream, generation, anchor, receive clock, decode clock and tick rate.
    pub scope: CatalogScope,
    /// Destination receive timestamp; every derived capture bound must precede it.
    pub receive_time: TimestampNs,
    /// Optional absolute time assumption for the earliest presentation sample across all pages.
    pub capture_origin: Option<RtspCaptureOrigin>,
    /// Cumulative page allowance, never renewed while loading the selection.
    pub max_pages: usize,
    /// Total windows across all pages; at most [`catalog::MAX_WINDOWS`].
    pub max_windows: usize,
    /// Total samples across all windows; at most [`catalog::MAX_FRAMES`].
    pub max_frames: usize,
    /// All catalog metadata and complete original windows; at most 128 MiB.
    pub max_original_bytes: u64,
    /// Complete reconstructed MP4, including initialization; at most 64 MiB.
    pub max_media_bytes: u64,
}
impl RtspCatalogPagesImportRequest {
    /// Pure exact-selection identity. Altered page order, clocks or bounds change the digest.
    pub fn digest(&self) -> Result<ContentDigest, RtspImportError> {
        self.selection()?.digest()
    }

    pub(super) fn selection(&self) -> Result<CatalogRequest, RtspImportError> {
        if !(1..=MAX_PAGES).contains(&self.max_pages)
            || self.pages.is_empty()
            || self.pages.len() > self.max_pages
        {
            return Err(RtspImportError::Invalid("catalog page count or ceiling"));
        }
        let first = &self.pages[0];
        let request = CatalogRequest::Pages {
            first: RtspCatalogImportRequest {
                codec: self.codec,
                slot: first.slot.clone(),
                root: first.root,
                scope: self.scope.clone(),
                receive_time: self.receive_time,
                capture_origin: self.capture_origin,
                max_windows: self.max_windows,
                max_frames: self.max_frames,
                max_original_bytes: self.max_original_bytes,
                max_media_bytes: self.max_media_bytes,
            },
            following: self.pages[1..].to_vec(),
            max_pages: self.max_pages,
        };
        request.validate()?;
        Ok(request)
    }
}

/// Current permission to read and retain every original in the exact complete page selection.
pub trait RtspCatalogPagesImportAuthority {
    /// Must enforce principal, privacy/retention policy, revocation and current deadline.
    fn permit(
        &self,
        request: &RtspCatalogPagesImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool;
}

/// Complete retained publication over the selected pages, with one global sample sequence.
#[derive(Debug)]
pub struct RtspCatalogPagesImportReceipt {
    /// Number of complete catalog roots and indexes retained in the publication closure.
    pub pages: usize,
    /// Existing complete-recording receipt, including total windows and native decode interval.
    pub catalog: RtspCatalogImportReceipt,
}

/// Import explicitly selected whole pages through the same native replay and root-last publisher.
/// No destination staging begins until every page, window, initialization and sample map passes.
pub fn import_rtsp_catalog_pages(
    publisher: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    request: &RtspCatalogPagesImportRequest,
    authority: &dyn RtspCatalogPagesImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<RtspCatalogPagesImportReceipt, RtspImportError> {
    let selection = request.selection()?;
    let catalog = catalog::import_selection(
        publisher,
        destination,
        &selection,
        &|current| authority.permit(request, current),
        cx,
        work,
    )?;
    Ok(RtspCatalogPagesImportReceipt {
        pages: selection.page_count(),
        catalog,
    })
}

/// Read-only campaign preflight through the exact same native page/recording verification as
/// import. Prepared payloads are dropped; publication always rechecks live original custody.
pub(crate) fn preflight_rtsp_catalog_pages(
    publisher: &LocalRootPublisher,
    destination: &ReferenceDeployment,
    request: &RtspCatalogPagesImportRequest,
    authority: &dyn RtspCatalogPagesImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<catalog::CatalogPreflight, RtspImportError> {
    catalog::preflight_selection(
        publisher,
        destination,
        &request.selection()?,
        &|current| authority.permit(request, current),
        cx,
        work,
    )
}

/// Versioned internal selection. Common fields use the first pin; all identity, encoding and scan
/// operations dispatch here so a multi-page selection can never reuse the first page's identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum CatalogRequest {
    Single(RtspCatalogImportRequest),
    Pages {
        first: RtspCatalogImportRequest,
        following: Vec<RtspCatalogPage>,
        max_pages: usize,
    },
}
impl Deref for CatalogRequest {
    type Target = RtspCatalogImportRequest;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Single(request) | Self::Pages { first: request, .. } => request,
        }
    }
}
impl CatalogRequest {
    pub(super) fn validate(&self) -> Result<(), RtspImportError> {
        self.deref().validate()?;
        if let Self::Pages {
            following,
            max_pages,
            ..
        } = self
        {
            if !(1..=MAX_PAGES).contains(max_pages)
                || following.len() >= *max_pages
                || self.page_count() > self.max_windows
            {
                return Err(RtspImportError::Invalid("catalog page count or ceiling"));
            }
            let mut roots = BTreeSet::from([self.root]);
            let mut slots = BTreeSet::from([&self.slot]);
            for page in following {
                if page.root.algorithm() != DigestAlgorithm::Sha256
                    || page.root.bytes() == [0; 32]
                    || !roots.insert(page.root)
                    || !slots.insert(&page.slot)
                {
                    return Err(RtspImportError::Invalid(
                        "duplicate or invalid catalog page",
                    ));
                }
            }
        }
        Ok(())
    }
    pub(super) fn page_count(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::Pages { following, .. } => following.len() + 1,
        }
    }
    pub(super) fn page_request(
        &self,
        index: usize,
    ) -> Result<RtspCatalogImportRequest, FileIngestError> {
        let mut request = self.deref().clone();
        if index > 0 {
            let Self::Pages { following, .. } = self else {
                return Err(corrupt("catalog page ordinal"));
            };
            let page = following
                .get(index - 1)
                .ok_or_else(|| corrupt("catalog page ordinal"))?;
            request.slot = page.slot.clone();
            request.root = page.root;
        }
        Ok(request)
    }
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        match self {
            Self::Single(request) => request.encode(e),
            Self::Pages {
                first,
                following,
                max_pages,
            } => {
                e.text(REQUEST_DOMAIN);
                first.encode(e);
                e.u64(*max_pages as u64);
                e.u64(following.len() as u64);
                for page in following {
                    e.text(page.slot.as_str());
                    e.digest(page.root);
                }
            }
        }
    }
    pub(super) fn digest(&self) -> Result<ContentDigest, RtspImportError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        self.encode(&mut e);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
    pub(super) fn identity(&self) -> Result<ContentDigest, RtspImportError> {
        match self {
            Self::Single(request) => request.identity(),
            Self::Pages { .. } => {
                let mut e = CanonicalEncoder::new();
                e.text("fss.rtsp_catalog_pages_import_identity.v1");
                e.digest(self.digest()?);
                Ok(ContentDigest::sha256(&e.finish_checked()?))
            }
        }
    }
    pub(super) fn scan(
        &self,
        media: &[u8],
        cx: &ReplayCx,
    ) -> Result<ScannedSegments, FileIngestError> {
        match self {
            Self::Single(request) => request.scan(media, cx),
            Self::Pages { .. } => scan_media(
                media,
                self.codec,
                &self.scope.recording,
                self.receive_time,
                self.capture_origin,
                self.max_frames,
                self.max_media_bytes,
                self.identity()
                    .map_err(|_| corrupt("catalog pages identity"))?,
                cx,
            ),
        }
    }
    pub(super) fn adapter(&self) -> &'static str {
        match self {
            Self::Single(_) => catalog::ADAPTER,
            Self::Pages { .. } => ADAPTER,
        }
    }
    pub(super) fn generation(&self) -> &'static str {
        match self {
            Self::Single(_) => catalog::GENERATION,
            Self::Pages { .. } => GENERATION,
        }
    }
    pub(super) fn evidence(&self) -> &'static str {
        match self {
            Self::Single(_) => catalog::EVIDENCE,
            Self::Pages { .. } => EVIDENCE,
        }
    }
    pub(super) fn catalog_work(&self) -> Result<u64, RtspImportError> {
        // Native catalog loading caps the root before reading its index; an invalid index may
        // still consume the existing 32 MiB object envelope. Reserve every selected page first.
        let per_page = match self {
            Self::Single(_) => super::MAX_ORIGINAL_BYTES,
            Self::Pages { .. } => super::MAX_ORIGINAL_BYTES + MAX_CATALOG_BYTES as u64,
        };
        per_page
            .checked_mul(self.page_count() as u64)
            .ok_or(RtspImportError::Invalid("catalog work overflow"))
    }
    pub(super) fn window_work(&self, count: usize) -> Result<u64, RtspImportError> {
        // The native owner checks cumulative bytes after each individually bounded read. A bad
        // final object can consume another object envelope before refusal; reserve it as well.
        let per_window = match self {
            Self::Single(_) => super::MAX_ORIGINAL_BYTES,
            Self::Pages { .. } => 2 * super::MAX_ORIGINAL_BYTES,
        };
        per_window
            .checked_mul(count as u64)
            .ok_or(RtspImportError::Invalid("catalog window work overflow"))
    }
}
