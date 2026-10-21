#![forbid(unsafe_code)]
//! Pure selected-recording admission and canonical whole-invocation reservations.

use std::collections::BTreeSet;

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{CanonicalEncoder, ContentDigest};

use super::{POLICY, Result, RtspSelectedWatchError};
use crate::ingest::long_dwell::limits::encode_limits;
use crate::ingest::long_watch::{LongWatchLimits, MAX_LONG_WATCH_FRAMES};
use crate::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use crate::ingest::rtsp_import::catalog::RtspCatalogImportRequest;
use crate::ingest::rtsp_import::pages::RtspCatalogPagesImportRequest;
use crate::ingest::rtsp_import::{
    RtspCaptureOrigin, RtspImportCodec, RtspImportError, RtspImportRequest,
};
use crate::rtsp::recording::RecordingScope;

/// Finite independent selections per invocation; selection order never implies continuity.
pub const MAX_SELECTIONS: usize = 16;
/// Complete metadata/candidate projection, never truncated to fit.
pub const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024 + 65536;
const MAX_TRACE_BYTES: u64 = 128 * 1024 * 1024;

/// One native source-verified import request. A page selection stays one recording with
/// continuous native timing inside it; tracking never bridges two outer selections.
#[derive(Clone, Debug)]
pub enum RtspWatchSelection {
    /// One complete independently sealed native recording window.
    Window(RtspImportRequest),
    /// One complete explicitly pinned native catalog.
    Catalog(RtspCatalogImportRequest),
    /// Ordered whole pages admitted by the existing continuity verifier.
    Pages(RtspCatalogPagesImportRequest),
}
impl RtspWatchSelection {
    /// Native request identity, binding every pin, clock, capture assumption and import ceiling.
    pub fn digest(&self) -> std::result::Result<ContentDigest, RtspImportError> {
        match self {
            Self::Window(request) => request.digest(),
            Self::Catalog(request) => request.digest(),
            Self::Pages(request) => request.digest(),
        }
    }
    /// Stable selection spelling, independent from codec.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Window(_) => "window",
            Self::Catalog(_) => "catalog",
            Self::Pages(_) => "pages",
        }
    }
    /// Explicit native codec owner, without sniffing or fallback.
    pub const fn codec(&self) -> RtspImportCodec {
        match self {
            Self::Window(r) => r.codec,
            Self::Catalog(r) => r.codec,
            Self::Pages(r) => r.codec,
        }
    }
    /// Original sensor/stream/generation and authority/receive-clock identities.
    pub fn source(&self) -> &RecordingScope {
        match self {
            Self::Window(r) => &r.source,
            Self::Catalog(r) => &r.scope.recording,
            Self::Pages(r) => &r.scope.recording,
        }
    }
    /// Explicit operator capture origin; this composition requires one for native watch.
    pub const fn capture_origin(&self) -> Option<RtspCaptureOrigin> {
        match self {
            Self::Window(r) => r.capture_origin,
            Self::Catalog(r) => r.capture_origin,
            Self::Pages(r) => r.capture_origin,
        }
    }
    /// Whole-selection sample ceiling, never refilled at a catalog or page boundary.
    pub const fn maximum_frames(&self) -> usize {
        match self {
            Self::Window(r) => r.max_frames,
            Self::Catalog(r) => r.max_frames,
            Self::Pages(r) => r.max_frames,
        }
    }
    pub(super) const fn maximum_original_bytes(&self) -> u64 {
        match self {
            Self::Window(r) => r.max_original_bytes,
            Self::Catalog(r) => r.max_original_bytes,
            Self::Pages(r) => r.max_original_bytes,
        }
    }
    pub(super) const fn maximum_media_bytes(&self) -> u64 {
        match self {
            Self::Window(r) => r.max_media_bytes,
            Self::Catalog(r) => r.max_media_bytes,
            Self::Pages(r) => r.max_media_bytes,
        }
    }
}

/// Complete exact selection and shared analysis choices. The caller separately binds the one
/// archive, destination, site, principal, whole import work account and operation deadline.
#[derive(Clone, Debug)]
pub struct RtspSelectedWatchPlan {
    /// One through sixteen independent exact native selections in owner-supplied order.
    pub selections: Vec<RtspWatchSelection>,
    /// AVC and HEVC require the native YCbCr interpretation.
    pub interpretation: ComponentInterpretation,
    /// Image zones evaluated independently in each selected recording.
    pub zones: Vec<WatchZone>,
    /// Shared thresholds; each selection starts with a fresh foreground model.
    pub detector: WatchDetectorConfig,
    /// Shared thresholds; tracker and local identities start independently per selection.
    pub tracker: WatchTrackerConfig,
    /// Native strict or explicitly tolerant decode handling.
    pub options: WatchOptions,
    /// Screen the privacy-masked frames through the existing conservative health path.
    pub screened: bool,
}

/// Fixed analysis allowance per selection and independent complete-report ceiling.
#[derive(Clone, Copy, Debug)]
pub struct RtspSelectedWatchLimits {
    /// Native source/decoder/pixel/assignment/trace limits, reserved for every selection up front.
    pub watch: LongWatchLimits,
    /// Whole combined JSON ceiling; no partial candidate inventory is returned.
    pub maximum_report_bytes: usize,
}
impl Default for RtspSelectedWatchLimits {
    fn default() -> Self {
        Self {
            watch: LongWatchLimits::default(),
            maximum_report_bytes: MAX_REPORT_BYTES,
        }
    }
}

/// Checked fixed ceilings for the complete invocation, not claimed observed usage. Native
/// analyses cannot borrow unused allowances from another selection; import work uses one account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtspSelectedWatchReservation {
    /// Number of independently selected recordings.
    pub selections: u32,
    /// Sum of complete-selection native sample ceilings.
    pub frames: u64,
    /// Sum of independently bounded original custody admissions.
    pub original_bytes: u64,
    /// Sum of complete reconstructed-media ceilings.
    pub media_bytes: u64,
    /// Sum of native analysis source-byte allowances.
    pub source_read_bytes: u64,
    /// Sum of foreground luma processing ceilings.
    pub pixel_samples: u64,
    /// Sum of separate screening luma ceilings; zero when screening is not selected.
    pub screening_pixel_samples: u64,
    /// Sum of deterministic assignment-work ceilings.
    pub assignment_work: u64,
    /// Sum of configured JPEG-work accounts; AVC/HEVC remain bounded by native decoder limits.
    pub jpeg_work: u64,
    /// Sum of retained native trace ceilings, at most 128 MiB.
    pub trace_bytes: u64,
    /// Independent complete projection bound.
    pub report_bytes: u64,
}

impl RtspSelectedWatchPlan {
    pub(super) fn watch_plan(&self, import: ContentDigest, frames: usize) -> WatchPlan {
        WatchPlan {
            import_identity: import,
            interpretation: self.interpretation,
            first_segment: 0,
            segment_count: frames,
            zones: self.zones.clone(),
            detector: self.detector,
            tracker: self.tracker,
        }
    }

    /// Admit every request, decode configuration and whole-invocation reservation before I/O.
    pub fn reservation(
        &self,
        limits: &RtspSelectedWatchLimits,
    ) -> Result<RtspSelectedWatchReservation> {
        if !(1..=MAX_SELECTIONS).contains(&self.selections.len())
            || self.interpretation != ComponentInterpretation::YCbCr
            || !(1..=MAX_REPORT_BYTES).contains(&limits.maximum_report_bytes)
        {
            return Err(RtspSelectedWatchError::Invalid(
                "selection count, interpretation or report limit",
            ));
        }
        limits.watch.validate()?;
        let decode = limits.watch.decode;
        let read = decode.read_limits;
        if decode.jpeg_work_units == 0
            || !(1..=512 * 1024 * 1024).contains(&read.max_source_bytes)
            || !(1..=16 * 1024 * 1024).contains(&read.max_chunk_bytes)
            || !(1..=16 * 1024 * 1024).contains(&read.max_segment_bytes)
        {
            return Err(RtspSelectedWatchError::Invalid(
                "native read or decode limits",
            ));
        }
        // Pure native constructors validate every codec field; no source bytes or clocks exist.
        fss_codec_h264::Decoder::new(decode.h264_limits)
            .map_err(|_| RtspSelectedWatchError::Invalid("AVC decoder limits"))?;
        fss_codec_h265::Decoder::new(decode.h265_limits)
            .map_err(|_| RtspSelectedWatchError::Invalid("HEVC decoder limits"))?;
        self.watch_plan(ContentDigest::sha256(POLICY), 1)
            .validate()?;
        let mut identities = BTreeSet::new();
        let mut frames = 0_u64;
        let mut original_bytes = 0_u64;
        let mut media_bytes = 0_u64;
        for selection in &self.selections {
            if !identities.insert(selection.digest()?)
                || selection.capture_origin().is_none()
                || selection.maximum_frames() > MAX_LONG_WATCH_FRAMES
            {
                return Err(RtspSelectedWatchError::Invalid(
                    "duplicate request, missing capture origin or whole-recording frame ceiling",
                ));
            }
            frames = frames
                .checked_add(selection.maximum_frames() as u64)
                .ok_or(RtspSelectedWatchError::Limit)?;
            original_bytes = original_bytes
                .checked_add(selection.maximum_original_bytes())
                .ok_or(RtspSelectedWatchError::Limit)?;
            media_bytes = media_bytes
                .checked_add(selection.maximum_media_bytes())
                .ok_or(RtspSelectedWatchError::Limit)?;
        }
        let n = self.selections.len() as u64;
        let reserve = |value: u64| n.checked_mul(value).ok_or(RtspSelectedWatchError::Limit);
        let trace_bytes = reserve(limits.watch.maximum_trace_bytes as u64)?;
        if trace_bytes > MAX_TRACE_BYTES {
            return Err(RtspSelectedWatchError::Limit);
        }
        Ok(RtspSelectedWatchReservation {
            selections: self.selections.len() as u32,
            frames,
            original_bytes,
            media_bytes,
            source_read_bytes: reserve(limits.watch.maximum_source_chunk_bytes)?,
            pixel_samples: reserve(limits.watch.maximum_pixel_samples)?,
            screening_pixel_samples: if self.screened {
                reserve(limits.watch.maximum_pixel_samples)?
            } else {
                0
            },
            assignment_work: reserve(limits.watch.maximum_assignment_work)?,
            jpeg_work: reserve(decode.jpeg_work_units)?,
            trace_bytes,
            report_bytes: limits.maximum_report_bytes as u64,
        })
    }

    /// Exact approval identity binds ordered native requests and every analysis/resource choice.
    pub fn digest(&self, limits: &RtspSelectedWatchLimits) -> Result<ContentDigest> {
        let reservation = self.reservation(limits)?;
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_selected_watch_plan.v1");
        e.digest(ContentDigest::sha256(POLICY));
        e.u32(reservation.selections);
        for selection in &self.selections {
            e.digest(selection.digest()?);
        }
        e.digest(self.watch_plan(ContentDigest::sha256(POLICY), 1).digest());
        e.bool(self.options.tolerate_decode_refusals);
        e.bool(self.screened);
        encode_limits(&mut e, &limits.watch);
        e.u64(limits.maximum_report_bytes as u64);
        let bytes = e
            .finish_checked()
            .map_err(|_| RtspSelectedWatchError::Limit)?;
        Ok(ContentDigest::sha256(&bytes))
    }
}
