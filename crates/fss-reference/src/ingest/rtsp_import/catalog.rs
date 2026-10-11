#![forbid(unsafe_code)]
//! Source-closed import of one complete, explicitly pinned RTSP catalog page.
//!
//! Adjacent native decode intervals and identical initialization bytes are required. The resulting
//! retained MP4 preserves all samples across archive windows, so whole-recording perception need not
//! reset its tracker every 256 frames. This proves neither physical coverage nor a capture clock.

use super::catalog_provenance::{CatalogProof, CatalogTable, WindowReference};
use super::publication::{PublicationInput, publish_import};
use super::*;
use crate::rtsp::recording_catalog::{CatalogScope, MAX_CATALOG_WINDOWS};
use std::ops::Range;

/// Separate adapter profile; existing single-window import identities and bytes are unchanged.
pub const ADAPTER: &str = "ADP-RTSP-CATALOG-ARCHIVE-001";
pub(crate) const GENERATION: &str = "gen:rtsp-catalog-archive:v1:";
pub(crate) const EVIDENCE: &str =
    "native_rtsp_catalog:continuous_multifragment_mp4:original_rtp_retained";
/// A complete bounded page, with independently source-verified recording windows.
pub const MAX_WINDOWS: usize = MAX_CATALOG_WINDOWS;
/// Whole-page sample ceiling; each independently sealed native window still admits at most 256.
pub const MAX_FRAMES: usize = MAX_WINDOWS * super::MAX_FRAMES;
/// Catalog plus all complete original windows; shared payloads count conservatively per window.
pub const MAX_ORIGINAL_BYTES: u64 = 128 * 1024 * 1024;
/// Complete initialization plus all fragments, never silently truncated to fit.
pub const MAX_MEDIA_BYTES: u64 = 64 * 1024 * 1024;

/// Exact whole catalog, clock declaration, capture assumption and cumulative import bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtspCatalogImportRequest {
    /// Explicit codec-specific catalog and native recording verifier; no metadata fallback.
    pub codec: RtspImportCodec,
    /// Exact durable catalog slot.
    pub slot: SlotName,
    /// Independently selected immutable catalog root.
    pub root: ContentDigest,
    /// Recording generation and explicitly declared decode-clock/time-scale identity.
    pub scope: CatalogScope,
    /// Destination receive timestamp; all capture bounds must precede it.
    pub receive_time: TimestampNs,
    /// Capture time of the earliest presentation sample across the complete page, if assumed.
    pub capture_origin: Option<RtspCaptureOrigin>,
    /// Whole-page window bound; excess refuses before source window reads.
    pub max_windows: usize,
    /// Whole-page sample bound, never renewed per window.
    pub max_frames: usize,
    /// Cumulative original custody allowance, including catalog metadata.
    pub max_original_bytes: u64,
    /// Whole reconstructed MP4 allowance.
    pub max_media_bytes: u64,
}
impl RtspCatalogImportRequest {
    /// Pure validation and canonical request identity; no I/O or implicit capability.
    pub fn digest(&self) -> Result<ContentDigest, RtspImportError> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        self.encode(&mut e);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
    pub(super) fn validate(&self) -> Result<(), RtspImportError> {
        if [
            self.root,
            self.scope.decode_clock,
            self.scope.recording.anchor,
            self.scope.recording.receive_clock,
        ]
        .iter()
        .any(|d| d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32])
            || self.scope.recording.generation == 0
            || self.scope.time_scale == 0
            || self.receive_time.0 < 0
            || !(1..=MAX_WINDOWS).contains(&self.max_windows)
            || !(1..=MAX_FRAMES).contains(&self.max_frames)
            || !(1..=MAX_ORIGINAL_BYTES).contains(&self.max_original_bytes)
            || !(1..=MAX_MEDIA_BYTES).contains(&self.max_media_bytes)
        {
            return Err(RtspImportError::Invalid("catalog scope, time or bounds"));
        }
        if let Some(h) = self.capture_origin {
            if h.start_ns.0 < 0
                || h.start_ns
                    .0
                    .checked_add(i128::from(h.uncertainty_ns))
                    .is_none()
            {
                return Err(RtspImportError::Invalid("catalog capture hint"));
            }
            FileIngestAdapter::compute_capture_interval(
                0,
                Some(&CaptureHint {
                    start_ns: h.start_ns,
                    uncertainty_ns: h.uncertainty_ns,
                    assumed_fps: 1.0,
                }),
                self.receive_time,
            )?;
        }
        Ok(())
    }
    pub(super) fn encode(&self, e: &mut CanonicalEncoder) {
        e.text("fss.rtsp_catalog_import_request.v1");
        e.text(self.codec.as_str());
        e.text(self.slot.as_str());
        e.digest(self.root);
        let s = &self.scope.recording;
        e.text(s.sensor.as_str());
        e.text(s.stream.as_str());
        e.u64(s.generation);
        e.digest(s.anchor);
        e.digest(s.receive_clock);
        e.digest(self.scope.decode_clock);
        e.u32(self.scope.time_scale);
        e.i128(self.receive_time.0);
        e.bool(self.capture_origin.is_some());
        if let Some(h) = self.capture_origin {
            e.i128(h.start_ns.0);
            e.u64(h.uncertainty_ns);
        }
        e.u64(self.max_windows as u64);
        e.u64(self.max_frames as u64);
        e.u64(self.max_original_bytes);
        e.u64(self.max_media_bytes);
    }
    pub(super) fn identity(&self) -> Result<ContentDigest, RtspImportError> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.rtsp_catalog_import_identity.v1");
        e.digest(self.digest()?);
        Ok(ContentDigest::sha256(&e.finish_checked()?))
    }
    pub(super) fn scan(
        &self,
        media: &[u8],
        cx: &ReplayCx,
    ) -> Result<ScannedSegments, FileIngestError> {
        scan_media(
            media,
            self.codec,
            &self.scope.recording,
            self.receive_time,
            self.capture_origin,
            self.max_frames,
            self.max_media_bytes,
            self.identity().map_err(|_| corrupt("catalog identity"))?,
            cx,
        )
    }
    pub(super) fn time_label(&self) -> &'static str {
        if self.capture_origin.is_some() {
            "operator_assumption"
        } else {
            "unknown"
        }
    }
}

/// Current permission to read original packets and retain them for this exact complete page.
pub trait RtspCatalogImportAuthority {
    /// Must enforce current principal, privacy/retention policy, revocation and deadline.
    fn permit(&self, request: &RtspCatalogImportRequest, destination: &ReferenceDeployment)
    -> bool;
}

/// One completed retained import spanning all verified adjacent windows in the page.
#[derive(Debug)]
pub struct RtspCatalogImportReceipt {
    /// Existing retained-media identity and exact publication/retry result.
    pub import: RtspImportReceipt,
    /// Number of complete original native recording windows retained.
    pub windows: usize,
    /// Declared continuous decode interval; not capture continuity or scene observability.
    pub decode_interval: Range<u64>,
}

struct CatalogAccess<'a> {
    request: &'a RtspCatalogImportRequest,
    destination: &'a ReferenceDeployment,
    authority: &'a dyn RtspCatalogImportAuthority,
    cx: &'a ReplayCx,
}
impl PublishCancellation for CatalogAccess<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        checkpoint(self.cx).is_err() || !self.authority.permit(self.request, self.destination)
    }
}

/// Verify one whole pinned catalog, join its original fragments and publish one retained import.
/// Native readers reserve their existing 32 MiB input envelope against one work account; independent
/// original/media/sample limits cover the whole page. No source mutation occurs. Destination staging
/// begins only after the complete native closure, continuity and reconstructed sample map pass.
pub fn import_rtsp_catalog(
    publisher: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    request: &RtspCatalogImportRequest,
    authority: &dyn RtspCatalogImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
) -> Result<RtspCatalogImportReceipt, RtspImportError> {
    request.validate()?;
    if cx.root_dir() != destination.root()
        || publisher.root_dir().starts_with(destination.root())
        || destination.root().starts_with(publisher.root_dir())
    {
        return Err(RtspImportError::Invalid(
            "distinct source and destination owners required",
        ));
    }
    let authorize = |current: &ReferenceDeployment| {
        checkpoint(cx)?;
        if !authority.permit(request, current) {
            return Err(RtspImportError::Denied);
        }
        Ok(())
    };
    authorize(destination)?;
    work.charge(super::MAX_ORIGINAL_BYTES)
        .map_err(source_error)?;
    let access = CatalogAccess {
        request,
        destination,
        authority,
        cx,
    };
    let table = CatalogTable::load(publisher, request, &access)?;
    let entries = table.entries(request)?;
    let frames: usize = entries.iter().map(|e| e.samples()).sum();
    let interval = entries
        .first()
        .ok_or(RtspImportError::Invalid("empty catalog"))?
        .decode_interval()
        .start
        ..entries
            .last()
            .ok_or(RtspImportError::Invalid("empty catalog"))?
            .decode_interval()
            .end;
    let mut media = Vec::new();
    let mut payloads = BTreeMap::new();
    table.insert_payloads(&mut payloads);
    let mut windows = Vec::with_capacity(entries.len());
    let mut initialization = None;
    for (ordinal, entry) in entries.iter().enumerate() {
        authorize(destination)?;
        work.charge(super::MAX_ORIGINAL_BYTES)
            .map_err(source_error)?;
        let single = RtspImportRequest {
            codec: request.codec,
            slot: entry.slot().clone(),
            root: entry.root(),
            source: request.scope.recording.clone(),
            receive_time: request.receive_time,
            capture_origin: None,
            max_frames: super::MAX_FRAMES,
            max_original_bytes: super::MAX_ORIGINAL_BYTES,
            max_media_bytes: super::MAX_MEDIA_BYTES,
        };
        let window = match request.codec {
            RtspImportCodec::Avc => {
                let p = load_recording(
                    publisher,
                    &single.slot,
                    single.root,
                    &single.source,
                    &access,
                )
                .map_err(source_error)?;
                CatalogTable::check_window(entry, request, p.summary(), p.byte_len())?;
                provenance::Window::from_verified(&p, &single)?
            }
            RtspImportCodec::Hevc => {
                let p = load_hevc_recording(
                    publisher,
                    &single.slot,
                    single.root,
                    &single.source,
                    &access,
                )
                .map_err(source_error)?;
                CatalogTable::check_window(entry, request, p.summary(), p.byte_len())?;
                provenance::Window::from_verified(p.publication_plan(), &single)?
            }
        };
        let config = ContentDigest::sha256(&window.initialization);
        match initialization {
            Some(previous) if previous != config => {
                return Err(RtspImportError::Invalid(
                    "catalog changes decoder initialization",
                ));
            }
            None => {
                append_media(&mut media, &window.initialization, request.max_media_bytes)?;
                initialization = Some(config);
            }
            _ => {}
        }
        append_fragment(
            &mut media,
            &window.fragment,
            ordinal,
            request.max_media_bytes,
        )?;
        windows.push(WindowReference::new(&window));
        for (digest, bytes) in window.payloads() {
            payloads.insert(digest, bytes.to_vec());
        }
    }
    drop(access);
    authorize(destination)?;
    work.charge((media.len() as u64).saturating_mul(2))
        .map_err(source_error)?;
    let scan = request.scan(&media, cx)?;
    if scan.capsules.len() != frames
        || scan.truncated_frames != 0
        || scan.segment_spans.iter().any(|s| s.gap_before)
        || scan
            .omission_spans
            .iter()
            .any(|s| !s.is_container_structure())
    {
        return Err(RtspImportError::Invalid(
            "complete continuous catalog sample map",
        ));
    }
    let proof = CatalogProof::new(request.clone(), table, windows, &media, &scan)?;
    let imported = publish_import(
        destination,
        cx,
        work,
        PublicationInput {
            identity: request.identity()?,
            limits_digest: request.digest()?,
            codec: request.codec,
            adapter: ADAPTER,
            generation: GENERATION,
            detector_evidence: EVIDENCE,
            capture_time_label: request.time_label(),
            frames,
            proof: proof.encode()?,
        },
        media,
        scan,
        payloads,
        &authorize,
    )?;
    Ok(RtspCatalogImportReceipt {
        import: imported,
        windows: entries.len(),
        decode_interval: interval,
    })
}

/// Append a natively verified independent recording fragment to a derived MP4.
/// Both native recording writers start each sealed window at movie-fragment sequence one.
/// Only that four-byte field changes in the derivative; original custody, sample data, timing,
/// sizes and offsets remain exact. The strict MP4 demux then verifies sequences across the page.
pub(super) fn append_fragment(
    out: &mut Vec<u8>,
    bytes: &[u8],
    ordinal: usize,
    maximum: u64,
) -> Result<(), FileIngestError> {
    if ordinal >= MAX_WINDOWS
        || bytes.get(4..8) != Some(b"moof")
        || bytes.get(8..12) != Some(&16_u32.to_be_bytes())
        || bytes.get(12..16) != Some(b"mfhd")
        || bytes.get(16..20) != Some(&[0; 4])
        || bytes.get(20..24) != Some(&1_u32.to_be_bytes())
    {
        return Err(corrupt("native catalog fragment sequence header"));
    }
    let sequence =
        u32::try_from(ordinal + 1).map_err(|_| corrupt("catalog fragment sequence bound"))?;
    let start = out.len();
    append_media(out, bytes, maximum)?;
    out[start + 20..start + 24].copy_from_slice(&sequence.to_be_bytes());
    Ok(())
}

pub(super) fn append_media(
    out: &mut Vec<u8>,
    bytes: &[u8],
    maximum: u64,
) -> Result<(), FileIngestError> {
    let next = out
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| corrupt("catalog media overflow"))?;
    if next as u64 > maximum {
        return Err(corrupt("catalog media ceiling"));
    }
    out.try_reserve_exact(bytes.len())
        .map_err(|_| corrupt("catalog media allocation"))?;
    out.extend_from_slice(bytes);
    Ok(())
}
