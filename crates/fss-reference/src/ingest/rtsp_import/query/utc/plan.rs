#![forbid(unsafe_code)]
//! Complete protected UTC selection and immutable native acquisition recipe.

use std::collections::BTreeSet;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest};
use fss_object::SpoolIo;

use super::*;
use crate::agent_recording_context::utc_discover::discover_recordings_utc_in_deployment;
use crate::agent_recording_context::utc_sessions::query_recordings_utc_sessions_in_deployment;
use crate::agent_recordings::RecordingQueryCodec;
use crate::ingest::rtsp_import::{self, RtspImportCodec};

const DOMAIN: &str = "fss.rtsp_utc_query_import_plan.v1";
const POLICY: &str = "protected-exact-utc-candidates:independent-source-clocks:whole-selected-native-windows:unknown-clock-candidates-preserved:conditional-metadata-not-capture-time:unchanged-native-child-identities:exact-descriptor-check:one-import-work-account:no-partial-catalog-or-clock:repreview-after-anchor-change:no-continuity:no-absence:no-media-delivery:v1";
type Result<T> = std::result::Result<T, RtspQueryImportError>;

/// Preview exact native candidates selected by existing protected conditional UTC owners.
///
/// Both variants retain their original source/time provenance and all unknown-clock rows.
/// Metadata is read without source payloads or writer recovery. Neither the returned plan
/// nor an original capture approval grants present original-read or destination authority.
#[allow(clippy::too_many_arguments)]
pub fn preview_rtsp_utc_query_import(
    io: &dyn SpoolIo,
    deployment_root: &Path,
    archive_root: &Path,
    input: &RtspUtcQueryImportInput,
    settings: &RtspQueryImportSettings,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<RtspUtcQueryImportPlan> {
    settings.validate()?;
    let max_windows = match input {
        RtspUtcQueryImportInput::Sessions { request, .. } => request.recording.max_windows,
        RtspUtcQueryImportInput::Discovery { request, .. } => request.recording.max_windows,
    };
    if !(1..=super::super::MAX_WINDOWS).contains(&max_windows) {
        return Err(RtspQueryImportError::Invalid(
            "complete UTC selection output bound",
        ));
    }
    if deployment_root.as_os_str().is_empty()
        || archive_root.as_os_str().is_empty()
        || deployment_root.to_str().is_none()
        || archive_root.to_str().is_none()
        || archive_root.starts_with(deployment_root)
        || deployment_root.starts_with(archive_root)
    {
        return Err(RtspQueryImportError::Invalid(
            "UTC query import owner scope",
        ));
    }
    if cancelled() {
        return Err(RtspQueryImportError::Denied);
    }
    let query = match input {
        RtspUtcQueryImportInput::Sessions { request, limits } => {
            RtspUtcQueryImportObservation::Sessions(
                query_recordings_utc_sessions_in_deployment(
                    io,
                    deployment_root,
                    archive_root,
                    request,
                    limits,
                    cancelled,
                )
                .map_err(|error| RtspQueryImportError::UtcSessionsContext(Box::new(error)))?,
            )
        }
        RtspUtcQueryImportInput::Discovery { request, limits } => {
            RtspUtcQueryImportObservation::Discovery(
                discover_recordings_utc_in_deployment(
                    io,
                    deployment_root,
                    archive_root,
                    request,
                    limits,
                    cancelled,
                )
                .map_err(|error| RtspQueryImportError::UtcDiscoveryContext(Box::new(error)))?,
            )
        }
    };
    if query.snapshot().site_lineage != settings.site {
        return Err(RtspQueryImportError::Invalid(
            "UTC query import destination site",
        ));
    }
    let mut windows = Vec::new();
    let quoted_bytes = match (&query, input) {
        (
            RtspUtcQueryImportObservation::Sessions(query),
            RtspUtcQueryImportInput::Sessions { .. },
        ) => {
            windows
                .try_reserve_exact(query.native.rows.len())
                .map_err(|_| RtspQueryImportError::Invalid("UTC selection allocation"))?;
            for selected in &query.native.rows {
                if cancelled() {
                    return Err(RtspQueryImportError::Denied);
                }
                let session = query
                    .native
                    .sessions
                    .get(selected.session_index)
                    .ok_or(RtspQueryImportError::Invalid("UTC session coordinates"))?;
                if selected.session_digest != session.session_digest {
                    return Err(RtspQueryImportError::Invalid("UTC session identity"));
                }
                windows.push(RtspUtcQueryImportWindow {
                    session_index: Some(selected.session_index),
                    session_digest: Some(selected.session_digest),
                    scope: session.scope.clone(),
                    clock_root: session.clock_root,
                    clock_metadata_digest: session.clock_metadata_digest,
                    row: selected.row.clone(),
                    request: native_request(
                        session.codec,
                        &session.scope,
                        &selected.row,
                        settings,
                    )?,
                });
            }
            query.native.quoted_hydration_bytes
        }
        (
            RtspUtcQueryImportObservation::Discovery(query),
            RtspUtcQueryImportInput::Discovery { request, .. },
        ) => {
            windows
                .try_reserve_exact(query.native.rows.len())
                .map_err(|_| RtspQueryImportError::Invalid("UTC selection allocation"))?;
            for row in &query.native.rows {
                if cancelled() {
                    return Err(RtspQueryImportError::Denied);
                }
                windows.push(RtspUtcQueryImportWindow {
                    session_index: None,
                    session_digest: None,
                    scope: request.recording.scope.clone(),
                    clock_root: query.native.clock_root,
                    clock_metadata_digest: query.native.clock_metadata_digest,
                    row: row.clone(),
                    request: native_request(
                        request.recording.codec,
                        &request.recording.scope,
                        row,
                        settings,
                    )?,
                });
            }
            query.native.quoted_hydration_bytes
        }
        _ => return Err(RtspQueryImportError::Invalid("UTC query variant")),
    };
    if windows.len() > super::super::MAX_WINDOWS {
        return Err(RtspQueryImportError::Invalid(
            "complete UTC selection output bound",
        ));
    }
    let mut roots = BTreeSet::new();
    let mut slots = BTreeSet::new();
    let mut frames = 0_usize;
    let mut original_bytes = 0_u64;
    for window in &windows {
        frames =
            frames
                .checked_add(window.row.entry.samples())
                .ok_or(RtspQueryImportError::Invalid(
                    "UTC selected sample overflow",
                ))?;
        original_bytes = original_bytes
            .checked_add(window.row.entry.byte_len() as u64)
            .ok_or(RtspQueryImportError::Invalid(
                "UTC selected original overflow",
            ))?;
        if frames > settings.max_frames
            || original_bytes > settings.max_original_bytes
            || !roots.insert(window.request.root)
            || !slots.insert(window.request.slot.clone())
        {
            return Err(RtspQueryImportError::Invalid(
                "UTC selected aggregate bounds or repeated source",
            ));
        }
    }
    if original_bytes != quoted_bytes
        || (windows.len() as u64)
            .checked_mul(rtsp_import::MAX_ORIGINAL_BYTES * 3)
            .and_then(|reads| reads.checked_add(original_bytes))
            .is_none_or(|minimum| minimum > settings.max_work)
    {
        return Err(RtspQueryImportError::Invalid(
            "UTC selected quote or minimum work reservation",
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
    encoder.digest(query.request_digest());
    encoder.digest(query.decision_digest());
    encoder.text(query.anchor_token());
    let expected_anchor = match input {
        RtspUtcQueryImportInput::Sessions { request, .. } => {
            encoder.text("sessions");
            &request.expected_anchor
        }
        RtspUtcQueryImportInput::Discovery { request, .. } => {
            encoder.text("discovery");
            &request.expected_anchor
        }
    };
    encoder.bool(expected_anchor.is_some());
    if let Some(anchor) = expected_anchor {
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
    encoder.text("read-only-pinned-five-object-native-closure:two-pass:cumulative:v1");
    let source_limits = super::super::batch::source_limits(
        windows.len(),
        original_bytes,
        windows
            .iter()
            .map(|window| window.row.entry.byte_len())
            .max()
            .unwrap_or(0),
    );
    for value in [
        source_limits.max_catalogue_entries as u64,
        source_limits.max_objects as u64,
        source_limits.max_edges as u64,
        source_limits.max_object_bytes as u64,
        source_limits.max_read_bytes,
        source_limits.max_io_calls,
    ] {
        encoder.u64(value);
    }
    for window in &windows {
        encoder.bool(window.session_index.is_some());
        if let Some(index) = window.session_index {
            encoder.u64(index as u64);
        }
        encoder.bool(window.session_digest.is_some());
        if let Some(digest) = window.session_digest {
            encoder.digest(digest);
        }
        encoder.digest(window.scope.decode_clock);
        encoder.u32(window.scope.time_scale);
        encoder.digest(window.clock_root);
        encoder.digest(window.clock_metadata_digest);
        encoder.digest(window.row.row_digest());
        encoder.digest(window.request.digest()?);
    }
    let bytes = encoder
        .finish_checked()
        .map_err(|_| RtspQueryImportError::Invalid("UTC canonical acquisition plan"))?;
    if cancelled() {
        return Err(RtspQueryImportError::Denied);
    }
    Ok(RtspUtcQueryImportPlan {
        deployment_root: deployment_root.to_path_buf(),
        archive_root: archive_root.to_path_buf(),
        input: input.clone(),
        settings: settings.clone(),
        query,
        windows,
        frames,
        original_bytes,
        digest: ContentDigest::sha256(&bytes),
    })
}

fn native_request(
    codec: RecordingQueryCodec,
    scope: &CatalogScope,
    row: &RecordingUtcSetQueryRow,
    settings: &RtspQueryImportSettings,
) -> Result<RtspImportRequest> {
    let request = RtspImportRequest {
        codec: match codec {
            RecordingQueryCodec::Avc => RtspImportCodec::Avc,
            RecordingQueryCodec::Hevc => RtspImportCodec::Hevc,
        },
        slot: row.entry.slot().clone(),
        root: row.entry.root(),
        source: scope.recording.clone(),
        receive_time: settings.receive_time,
        // Node read/admission envelopes and unknown clocks never become camera capture hints.
        capture_origin: None,
        max_frames: row.entry.samples(),
        max_original_bytes: row.entry.byte_len() as u64,
        max_media_bytes: settings
            .max_media_bytes
            .min(rtsp_import::MAX_MEDIA_BYTES)
            .min(row.entry.byte_len() as u64),
    };
    request.digest()?;
    Ok(request)
}
