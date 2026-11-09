#![forbid(unsafe_code)]
//! Metadata-only planning and complete canonical acquisition commitments.

use std::collections::BTreeSet;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::SpoolIo;

use super::*;
use crate::agent_recording_context::query_recordings_in_deployment;
use crate::agent_recordings::RecordingQueryCodec;
use crate::ingest::rtsp_import::{self, RtspImportCodec};
use crate::reference_deployment::validate_site_lineage;

type Result<T> = std::result::Result<T, RtspQueryImportError>;

impl RtspQueryImportSettings {
    pub(super) fn validate(&self) -> Result<()> {
        if validate_site_lineage(&self.site).is_err()
            || self.receive_time.0 < 0
            || !(1..=rtsp_import::catalog::MAX_FRAMES).contains(&self.max_frames)
            || !(1..=rtsp_import::catalog::MAX_ORIGINAL_BYTES).contains(&self.max_original_bytes)
            || !(1..=rtsp_import::catalog::MAX_MEDIA_BYTES).contains(&self.max_media_bytes)
        {
            return Err(RtspQueryImportError::Invalid("query import settings"));
        }
        Ok(())
    }
}

/// Read protected metadata from an existing deployment and one exactly pinned native catalog.
///
/// This invokes the existing bounded AOP-005 context/query owner. It never opens a publisher,
/// creates a deployment, reads encoded media, infers UTC, or grants retention permission.
/// Paths, current deployment anchor, all limits, selected rows, indexed gaps, acquisition
/// settings and unchanged native child requests are committed by the returned plan.
#[allow(clippy::too_many_arguments)]
pub fn preview_rtsp_query_import(
    io: &dyn SpoolIo,
    deployment_root: &Path,
    archive_root: &Path,
    request: &RecordingContextRequest,
    limits: &RecordingContextLimits,
    settings: &RtspQueryImportSettings,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspQueryImportPlan> {
    settings.validate()?;
    if !(1..=MAX_WINDOWS).contains(&request.recording.max_windows)
        || deployment_root.as_os_str().is_empty()
        || archive_root.as_os_str().is_empty()
        || deployment_root.to_str().is_none()
        || archive_root.to_str().is_none()
        || archive_root.starts_with(deployment_root)
        || deployment_root.starts_with(archive_root)
    {
        return Err(RtspQueryImportError::Invalid("query import owner scope"));
    }
    if cancelled() {
        return Err(RtspQueryImportError::Denied);
    }
    let query = query_recordings_in_deployment(
        io,
        deployment_root,
        archive_root,
        request,
        limits,
        cancelled,
    )?;
    if query.snapshot.site_lineage != settings.site {
        return Err(RtspQueryImportError::Invalid(
            "query import destination site",
        ));
    }
    let codec = match request.recording.codec {
        RecordingQueryCodec::Avc => RtspImportCodec::Avc,
        RecordingQueryCodec::Hevc => RtspImportCodec::Hevc,
    };
    let mut frames = 0_usize;
    let mut original_bytes = 0_u64;
    let mut roots = BTreeSet::new();
    let mut slots = BTreeSet::new();
    let mut windows = Vec::with_capacity(query.native.rows.len());
    for row in &query.native.rows {
        if cancelled() {
            return Err(RtspQueryImportError::Denied);
        }
        frames = frames
            .checked_add(row.entry.samples())
            .ok_or(RtspQueryImportError::Invalid(
                "selected sample count overflow",
            ))?;
        original_bytes = original_bytes
            .checked_add(row.entry.byte_len() as u64)
            .ok_or(RtspQueryImportError::Invalid(
                "selected original byte overflow",
            ))?;
        if frames > settings.max_frames
            || original_bytes > settings.max_original_bytes
            || !roots.insert(row.entry.root())
            || !slots.insert(row.entry.slot().clone())
        {
            return Err(RtspQueryImportError::Invalid(
                "selected windows exceed aggregate bounds or repeat",
            ));
        }
        let native = RtspImportRequest {
            codec,
            slot: row.entry.slot().clone(),
            root: row.entry.root(),
            source: request.recording.scope.recording.clone(),
            receive_time: settings.receive_time,
            capture_origin: None,
            max_frames: row.entry.samples(),
            max_original_bytes: row.entry.byte_len() as u64,
            // Static per-child bound preserves its native identity after an outer re-preview.
            // The aggregate actual media size is independently checked before each publication.
            max_media_bytes: settings
                .max_media_bytes
                .min(rtsp_import::MAX_MEDIA_BYTES)
                .min(row.entry.byte_len() as u64),
        };
        native.digest()?;
        windows.push(RtspQueryImportWindow {
            row: row.clone(),
            request: native,
        });
    }
    if original_bytes != query.native.quoted_hydration_bytes
        || (windows.len() as u64)
            .checked_mul(rtsp_import::MAX_ORIGINAL_BYTES)
            .and_then(|native_reads| native_reads.checked_add(original_bytes))
            .is_none_or(|minimum| minimum > settings.max_work)
    {
        return Err(RtspQueryImportError::Invalid(
            "selected custody quote or native work reservation",
        ));
    }

    let mut encoder = CanonicalEncoder::new();
    encoder.text(DOMAIN);
    encoder.text(POLICY);
    encoder.text(
        deployment_root
            .to_str()
            .ok_or(RtspQueryImportError::Invalid("destination path encoding"))?,
    );
    encoder.text(
        archive_root
            .to_str()
            .ok_or(RtspQueryImportError::Invalid("archive path encoding"))?,
    );
    encoder.digest(query.request_digest);
    encoder.digest(query.decision_digest);
    encoder.digest(query.native.request_digest);
    encoder.digest(query.native.decision_digest);
    encoder.text(&query.anchor_token);
    encoder.bool(request.expected_anchor.is_some());
    if let Some(anchor) = &request.expected_anchor {
        encoder.text(anchor.as_str());
    }
    encoder.text(&settings.site);
    encoder.i128(settings.receive_time.0);
    encoder.u64(settings.max_frames as u64);
    encoder.u64(settings.max_original_bytes);
    encoder.u64(settings.max_media_bytes);
    encoder.u64(settings.max_work);
    encoder.u64(frames as u64);
    encoder.u64(original_bytes);
    encoder.u64(windows.len() as u64);
    for window in &windows {
        encoder.digest(window.row.row_digest());
        encoder.digest(window.request.digest()?);
    }
    encoder.u64(query.native.indexed_gaps.len() as u64);
    for gap in &query.native.indexed_gaps {
        encoder.u64(gap.start);
        encoder.u64(gap.end);
    }
    encoder.u64(query.native.reference_digests.len() as u64);
    for digest in &query.native.reference_digests {
        encoder.digest(*digest);
    }
    let bytes = encoder
        .finish_checked()
        .map_err(|_| RtspQueryImportError::Invalid("query import canonical plan"))?;
    if cancelled() {
        return Err(RtspQueryImportError::Denied);
    }
    Ok(RtspQueryImportPlan {
        deployment_root: deployment_root.to_path_buf(),
        archive_root: archive_root.to_path_buf(),
        request: request.clone(),
        limits: *limits,
        settings: settings.clone(),
        query,
        windows,
        frames,
        original_bytes,
        digest: ContentDigest::sha256(&bytes),
    })
}
