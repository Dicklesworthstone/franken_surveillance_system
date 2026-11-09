#![forbid(unsafe_code)]
//! Explicit gap-preserving native catalog imports for review of interrupted recordings.
//!
//! This profile keeps native decode/presentation coordinates, marks each discontinuity on
//! both the retained sample and its source capsule, and never joins decoder state across a gap.
//! It accepts only complete independently replayed windows with identical initialization.
//! Existing continuous catalog requests, approvals and proof encodings remain unchanged.

use super::catalog::{self, RtspCatalogImportReceipt, RtspCatalogImportRequest};
use super::pages::{CatalogRequest, RtspCatalogPagesImportRequest};
use super::*;
use crate::rtsp::recording_catalog::CatalogEntry;
use fss_container::demux::{AvcMp4, DemuxError};
use std::collections::BTreeSet;
use std::ops::Range;

/// Distinct retained-origin profile; it grants no live-device or continuity qualification.
pub const ADAPTER: &str = "ADP-RTSP-GAPPED-CATALOG-001";
pub(crate) const GENERATION: &str = "gen:rtsp-gapped-catalog:v1:";
pub(super) const REQUEST_DOMAIN: &str = "fss.rtsp_gapped_catalog_import_request.v1";
pub(super) const PROOF_DOMAIN: &str = "fss.rtsp_gapped_catalog_import.v1";
pub(super) const IDENTITY_DOMAIN: &str = "fss.rtsp_gapped_catalog_import_identity.v1";
pub(super) const EVIDENCE: &str =
    "native_rtsp_gapped_catalog:gap_preserving_multifragment_mp4:original_rtp_retained";

/// A separately authorized complete catalog selection whose decode gaps must remain visible.
///
/// Wrapping an existing request never inherits its continuous-profile approval. Zero-gap inputs
/// are permitted, but still receive this profile's distinct identity and retained origin proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RtspGappedCatalogImportRequest {
    /// One exact complete native catalog.
    Catalog(RtspCatalogImportRequest),
    /// Explicitly ordered complete pages under one source and decode-clock scope.
    Pages(RtspCatalogPagesImportRequest),
}
impl RtspGappedCatalogImportRequest {
    /// Pure canonical request identity, including the explicit gap-preservation policy.
    pub fn digest(&self) -> Result<ContentDigest, RtspImportError> {
        self.selection()?.digest()
    }

    /// Number of explicitly selected complete pages, before request validation or I/O.
    #[must_use]
    pub fn page_count(&self) -> usize {
        match self {
            Self::Catalog(_) => 1,
            Self::Pages(request) => request.pages.len(),
        }
    }

    fn selection(&self) -> Result<CatalogRequest, RtspImportError> {
        let inner = match self {
            Self::Catalog(request) => CatalogRequest::Single(request.clone()),
            Self::Pages(request) => request.selection()?,
        };
        let selection = CatalogRequest::Gapped(Box::new(inner));
        selection.validate()?;
        Ok(selection)
    }
}

/// Current permission for this exact gap-preserving request and destination owner.
pub trait RtspGappedCatalogImportAuthority {
    /// Enforce principal, current privacy/retention policy, revocation and deadline.
    fn permit(
        &self,
        request: &RtspGappedCatalogImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool;
}

/// Completed source-closed import with explicit native decode-clock discontinuities.
#[derive(Debug)]
pub struct RtspGappedCatalogImportReceipt {
    /// Complete catalog roots and indexes retained in the import closure.
    pub pages: usize,
    /// Existing import result; its decode interval is a hull and does not imply continuity.
    pub catalog: RtspCatalogImportReceipt,
    /// Ordered nonempty half-open holes between native windows, in the declared decode clock.
    /// No capture-time, physical absence or camera coverage assertion follows from these holes.
    pub decode_gaps: Vec<Range<u64>>,
}

/// Replay complete native windows, preserve their timing/gaps, and publish one retained import.
///
/// Every source, count, byte, cancellation and root-last publication gate is shared with the
/// continuous importer. Overlapping/out-of-order windows and decoder configuration changes
/// still refuse before staging. The exact gap-preserving authority is rechecked throughout.
pub fn import_rtsp_gapped_catalog(
    publisher: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    request: &RtspGappedCatalogImportRequest,
    authority: &dyn RtspGappedCatalogImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<RtspGappedCatalogImportReceipt, RtspImportError> {
    let selection = request.selection()?;
    let (catalog, decode_gaps) = catalog::import_selection_with_gaps(
        publisher,
        destination,
        &selection,
        &|current| authority.permit(request, current),
        cx,
        work,
    )?;
    Ok(RtspGappedCatalogImportReceipt {
        pages: selection.page_count(),
        catalog,
        decode_gaps,
    })
}

pub(super) fn intervals(entries: &[CatalogEntry]) -> Vec<Range<u64>> {
    entries
        .windows(2)
        .filter_map(|pair| {
            let start = pair[0].decode_interval().end;
            let end = pair[1].decode_interval().start;
            (start < end).then_some(start..end)
        })
        .collect()
}

/// The exact first sample after each catalog discontinuity. Sample counts are native witnesses,
/// not estimates from frame rates or host time, and remain bound inside the origin proof.
pub(super) fn sample_indices(entries: &[CatalogEntry]) -> Result<BTreeSet<usize>, FileIngestError> {
    let mut indices = BTreeSet::new();
    let mut samples = 0_usize;
    let mut previous_end = None;
    for entry in entries {
        let interval = entry.decode_interval();
        if previous_end.is_some_and(|end| end > interval.start) {
            return Err(corrupt("overlapping catalog decode intervals"));
        }
        if previous_end.is_some_and(|end| end < interval.start) {
            indices.insert(samples);
        }
        samples = samples
            .checked_add(entry.samples())
            .ok_or_else(|| corrupt("catalog sample count overflow"))?;
        previous_end = Some(interval.end);
    }
    Ok(indices)
}

/// Mark only independently reparsed MP4 decode discontinuities. The caller additionally compares
/// these positions to every source-verified native catalog boundary before publication/replay.
pub(super) fn mark_scan(
    request: &CatalogRequest,
    media: &[u8],
    scan: &mut ScannedSegments,
    cx: &ReplayCx,
) -> Result<(), FileIngestError> {
    let mut limits = super::super::file_adapter::mp4_demux_limits(request.max_frames);
    limits.maximum_input_bytes = usize::try_from(request.max_media_bytes)
        .map_err(|_| corrupt("gapped catalog media ceiling"))?;
    let mut check = || {
        cx.checkpoint(STAGE_RTSP_IMPORT)
            .map_err(|_| DemuxError::Cancelled)
    };
    let video = AvcMp4::parse_with_checkpoint(media, None, limits, &mut check)
        .map_err(|refusal| FileIngestError::Mp4Refused { refusal })?;
    if video.samples().len() != scan.segment_spans.len()
        || scan.capsules.len() != scan.segment_spans.len()
    {
        return Err(corrupt("gapped catalog sample count"));
    }
    let mut previous_end = None;
    for (index, sample) in video.samples().iter().enumerate() {
        checkpoint(cx)?;
        if previous_end.is_some_and(|end| end > sample.decode_time) {
            return Err(corrupt("overlapping native sample decode intervals"));
        }
        let gap = previous_end.is_some_and(|end| end < sample.decode_time);
        if gap && (!sample.sync_sample || !sample.contains_idr) {
            return Err(corrupt(
                "decode gap must restart at a native random-access sample",
            ));
        }
        scan.segment_spans[index].gap_before = gap;
        scan.capsules[index].gap_before = gap;
        previous_end = Some(
            sample
                .decode_time
                .checked_add(u64::from(sample.duration))
                .ok_or_else(|| corrupt("native decode interval overflow"))?,
        );
    }
    Ok(())
}

pub(super) fn verify_scan(
    request: &CatalogRequest,
    entries: &[CatalogEntry],
    scan: &ScannedSegments,
) -> Result<(), FileIngestError> {
    let indices = sample_indices(entries)?;
    let samples = entries.iter().try_fold(0_usize, |count, entry| {
        count
            .checked_add(entry.samples())
            .ok_or_else(|| corrupt("catalog sample count overflow"))
    })?;
    if (!request.preserves_gaps() && !indices.is_empty())
        || scan.segment_spans.len() != samples
        || scan.segment_spans.len() != scan.capsules.len()
        || scan
            .segment_spans
            .iter()
            .zip(&scan.capsules)
            .enumerate()
            .any(|(index, (span, capsule))| {
                let expected = indices.contains(&index);
                span.gap_before != expected || capsule.gap_before != expected
            })
    {
        return Err(corrupt("native catalog gap witnesses differ from samples"));
    }
    Ok(())
}
