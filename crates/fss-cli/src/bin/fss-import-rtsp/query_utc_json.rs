#![forbid(unsafe_code)]
//! Complete bounded UTC selection output; every conditional source clock remains separate.

use std::collections::BTreeSet;
use std::ops::Range;

use fss_cli::agent_json::{array, object, string};
use fss_core::ContentDigest;
use fss_publication::custody_audit::CustodyAuditLimits;
use fss_reference::agent_recordings::set::RecordingSetCatalog;
use fss_reference::ingest::rtsp_import::query::utc::{
    RtspUtcQueryImportInput, RtspUtcQueryImportObservation, RtspUtcQueryImportPlan,
    RtspUtcQueryImportWindow, RtspUtcQueryImportedWindow,
};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use fss_reference::site::clock::{ClockCorrelationPolicy, ClockOffsetInterval};

use super::super::{FORMAT, UtcOptions};

fn digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".into(), |value| string(&value.to_text()))
}

fn ordinal(value: Option<usize>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn interval(value: &Range<u64>) -> String {
    object(&[
        ("start", string(&value.start.to_string())),
        ("end", string(&value.end.to_string())),
    ])
}

fn gaps(values: &[Range<u64>]) -> String {
    array(&values.iter().map(interval).collect::<Vec<_>>())
}

fn scope(value: &CatalogScope) -> String {
    object(&[
        ("sensor", string(value.recording.sensor.as_str())),
        ("stream", string(value.recording.stream.as_str())),
        (
            "generation",
            string(&value.recording.generation.to_string()),
        ),
        ("source_anchor", string(&value.recording.anchor.to_text())),
        (
            "receive_clock",
            string(&value.recording.receive_clock.to_text()),
        ),
        ("decode_clock", string(&value.decode_clock.to_text())),
        ("time_scale", value.time_scale.to_string()),
    ])
}

fn clock_policy(policy: ClockCorrelationPolicy, offset: ClockOffsetInterval) -> String {
    object(&[
        (
            "max_sample_bracket_ns",
            string(&policy.max_sample_bracket_ns.to_string()),
        ),
        ("max_drift_ppb", string(&policy.max_drift_ppb.to_string())),
        ("max_age_ns", string(&policy.max_age_ns.to_string())),
        (
            "utc_minus_local_lower_ns",
            string(&offset.lower_ns.to_string()),
        ),
        (
            "utc_minus_local_upper_ns",
            string(&offset.upper_ns.to_string()),
        ),
        (
            "authentication",
            string("unauthenticated_retained_node_clock"),
        ),
    ])
}

fn catalogs(values: &[RecordingSetCatalog], selected: &BTreeSet<usize>) -> String {
    array(
        &values
            .iter()
            .enumerate()
            .filter(|(index, _)| selected.contains(index))
            .map(|(index, value)| {
                object(&[
                    ("catalog_index", index.to_string()),
                    ("slot", string(value.pin.slot.as_str())),
                    ("root", string(&value.pin.root.to_text())),
                    ("metadata", string(&value.metadata_digest.to_text())),
                    ("scanned_windows", value.scanned_windows.to_string()),
                ])
            })
            .collect::<Vec<_>>(),
    )
}

pub(super) fn source_limits(limits: CustodyAuditLimits) -> String {
    object(&[
        ("max_pinned_roots", limits.max_catalogue_entries.to_string()),
        ("max_objects", limits.max_objects.to_string()),
        ("max_edges", limits.max_edges.to_string()),
        ("max_object_bytes", limits.max_object_bytes.to_string()),
        ("max_read_bytes", limits.max_read_bytes.to_string()),
        ("max_io_calls", limits.max_io_calls.to_string()),
        (
            "scope",
            string("one_nonrefillable_selected_source_reader_including_revalidation"),
        ),
    ])
}

pub(super) fn window(value: &RtspUtcQueryImportWindow) -> Result<String, &'static str> {
    let row = &value.row;
    let utc = row.utc_interval.map_or_else(
        || "null".into(),
        |utc| {
            object(&[
                ("earliest_ns", string(&utc.earliest_ns.to_string())),
                ("latest_ns", string(&utc.latest_ns.to_string())),
                ("endpoints", string("inclusive")),
            ])
        },
    );
    let locations = array(
        &row.locations
            .iter()
            .map(|location| {
                object(&[
                    ("catalog_index", location.catalog_index.to_string()),
                    ("catalog_root", string(&location.catalog_root.to_text())),
                    ("ordinal", location.ordinal.to_string()),
                ])
            })
            .collect::<Vec<_>>(),
    );
    Ok(object(&[
        ("session_index", ordinal(value.session_index)),
        ("session_digest", digest(value.session_digest)),
        ("source", scope(&value.scope)),
        ("codec", string(value.request.codec.as_str())),
        ("window_slot", string(value.request.slot.as_str())),
        ("window_root", string(&value.request.root.to_text())),
        ("decode_interval", interval(&row.entry.decode_interval())),
        ("catalog_memberships", locations),
        ("clock_root", string(&value.clock_root.to_text())),
        (
            "clock_metadata",
            string(&value.clock_metadata_digest.to_text()),
        ),
        ("clock_ordinal", ordinal(row.clock_ordinal)),
        (
            "clock_state",
            string(if row.utc_interval.is_some() {
                "conditional_node_observation"
            } else {
                "clock_unavailable"
            }),
        ),
        ("conditional_utc_interval", utc),
        ("quoted_original_bytes", row.entry.byte_len().to_string()),
        ("frames", row.entry.samples().to_string()),
        ("packets", row.entry.packets().to_string()),
        ("nals", row.entry.nals().to_string()),
        ("row_digest", string(&row.row_digest().to_text())),
        (
            "request_digest",
            string(
                &value
                    .request
                    .digest()
                    .map_err(|_| "ERR-RTSP-IMPORT-REQUEST-001")?
                    .to_text(),
            ),
        ),
    ]))
}

pub(super) fn imported(rows: &[RtspUtcQueryImportedWindow]) -> Result<String, &'static str> {
    Ok(array(
        &rows
            .iter()
            .map(|row| {
                let value = &row.import;
                Ok(object(&[
                    ("selection", window(&row.selection)?),
                    ("import_identity", string(&value.import_identity.to_text())),
                    ("import_root", string(&value.import_root.to_text())),
                    ("manifest_digest", string(&value.manifest_digest.to_text())),
                    ("origin_proof", string(&value.proof.to_text())),
                    ("frames", value.frames.to_string()),
                    ("codec", string(value.codec.as_str())),
                    ("capture_time_label", string(value.capture_time_label)),
                    ("reused", value.reused.to_string()),
                ]))
            })
            .collect::<Result<Vec<_>, &'static str>>()?,
    ))
}

pub(super) fn base(
    options: &UtcOptions,
    plan: &RtspUtcQueryImportPlan,
) -> Result<Vec<(&'static str, String)>, &'static str> {
    let (query_interval, maximum_windows) = match &options.input {
        RtspUtcQueryImportInput::Sessions { request, .. } => {
            (&request.recording.interval, request.recording.max_windows)
        }
        RtspUtcQueryImportInput::Discovery { request, .. } => {
            (&request.recording.interval, request.recording.max_windows)
        }
    };
    let mut contexts = Vec::new();
    let (selection_mode, indexed_gaps, scanned, unique, namespace, inventory) = match plan.query() {
        RtspUtcQueryImportObservation::Sessions(query) => {
            for (index, session) in query.native.sessions.iter().enumerate() {
                let selected = query
                    .native
                    .rows
                    .iter()
                    .filter(|row| row.session_index == index)
                    .flat_map(|row| {
                        row.row
                            .locations
                            .iter()
                            .map(|location| location.catalog_index)
                    })
                    .collect();
                contexts.push(object(&[
                    ("session_index", index.to_string()),
                    ("session_digest", string(&session.session_digest.to_text())),
                    ("codec", string(session.codec.as_str())),
                    ("source", scope(&session.scope)),
                    ("clock_slot", string(session.clock_slot.as_str())),
                    ("clock_root", string(&session.clock_root.to_text())),
                    (
                        "clock_metadata",
                        string(&session.clock_metadata_digest.to_text()),
                    ),
                    (
                        "historical_clock_approval",
                        string(&session.clock_approval_digest.to_text()),
                    ),
                    (
                        "clock_policy",
                        clock_policy(session.clock_policy, session.clock_offset),
                    ),
                    ("clock_brackets", session.clock_brackets.to_string()),
                    ("clock_windows", session.clock_windows.to_string()),
                    ("indexed_gaps", gaps(&session.indexed_gaps)),
                    ("verified_catalog_count", session.catalogs.len().to_string()),
                    ("selected_catalogs", catalogs(&session.catalogs, &selected)),
                    ("scanned_windows", session.scanned_windows.to_string()),
                    ("unique_windows", session.unique_windows.to_string()),
                    (
                        "quoted_original_bytes",
                        session.quoted_hydration_bytes.to_string(),
                    ),
                ]));
            }
            (
                "exact_sessions",
                &query.native.indexed_gaps,
                query.native.scanned_windows,
                query.native.unique_windows,
                None,
                None,
            )
        }
        RtspUtcQueryImportObservation::Discovery(query) => {
            let RtspUtcQueryImportInput::Discovery { request, .. } = &options.input else {
                return Err("ERR-RTSP-IMPORT-REQUEST-001");
            };
            let selected = query
                .native
                .rows
                .iter()
                .flat_map(|row| row.locations.iter().map(|location| location.catalog_index))
                .collect();
            contexts.push(object(&[
                ("codec", string(request.recording.codec.as_str())),
                ("source", scope(&request.recording.scope)),
                ("clock_slot", string(request.recording.clock_slot.as_str())),
                ("clock_root", string(&query.native.clock_root.to_text())),
                (
                    "clock_metadata",
                    string(&query.native.clock_metadata_digest.to_text()),
                ),
                (
                    "historical_clock_approval",
                    string(&query.native.clock_approval_digest.to_text()),
                ),
                (
                    "clock_policy",
                    clock_policy(query.native.clock_policy, query.native.clock_offset),
                ),
                ("clock_brackets", query.native.clock_brackets.to_string()),
                ("clock_windows", query.native.clock_windows.to_string()),
                ("indexed_gaps", gaps(&query.native.indexed_gaps)),
                (
                    "verified_catalog_count",
                    query.native.catalogs.len().to_string(),
                ),
                (
                    "selected_catalogs",
                    catalogs(&query.native.catalogs, &selected),
                ),
                (
                    "scanned_root_entries",
                    query.native.scanned_root_entries.to_string(),
                ),
            ]));
            (
                "complete_source_namespace",
                &query.native.indexed_gaps,
                query.native.scanned_windows,
                query.native.unique_windows,
                Some(query.native.namespace_digest),
                Some(query.native.inventory_digest),
            )
        }
    };
    Ok(vec![
        ("format", string(FORMAT)),
        (
            "approval_digest",
            string(&options.approval(plan.digest())?.to_text()),
        ),
        ("plan_digest", string(&plan.digest().to_text())),
        (
            "query_request",
            string(&plan.query().request_digest().to_text()),
        ),
        (
            "query_decision",
            string(&plan.query().decision_digest().to_text()),
        ),
        ("deployment_anchor", string(plan.query().anchor_token())),
        (
            "archive",
            string(
                options
                    .archive
                    .to_str()
                    .ok_or("ERR-RTSP-IMPORT-REQUEST-001")?,
            ),
        ),
        (
            "root",
            string(options.root.to_str().ok_or("ERR-RTSP-IMPORT-REQUEST-001")?),
        ),
        ("site", string(&options.settings.site)),
        ("principal", string(&options.principal)),
        (
            "receive_time_ns",
            string(&options.settings.receive_time.0.to_string()),
        ),
        ("selection_mode", string(selection_mode)),
        ("query_utc_interval", interval(query_interval)),
        ("query_endpoints", string("half_open")),
        ("namespace_digest", digest(namespace)),
        ("inventory_digest", digest(inventory)),
        ("source_contexts", array(&contexts)),
        ("indexed_gaps", gaps(indexed_gaps)),
        ("scanned_windows", scanned.to_string()),
        ("unique_indexed_windows", unique.to_string()),
        ("selected_frames", plan.frames().to_string()),
        ("selected_windows_count", plan.windows().len().to_string()),
        (
            "unknown_clock_candidates",
            plan.windows()
                .iter()
                .filter(|window| window.row.utc_interval.is_none())
                .count()
                .to_string(),
        ),
        ("quoted_original_bytes", plan.original_bytes().to_string()),
        (
            "quoted_bytes_scope",
            string("selected_retained_payloads_not_total_disk_io"),
        ),
        ("maximum_windows", maximum_windows.to_string()),
        ("maximum_frames", options.settings.max_frames.to_string()),
        (
            "maximum_original_bytes",
            options.settings.max_original_bytes.to_string(),
        ),
        (
            "maximum_media_bytes",
            options.settings.max_media_bytes.to_string(),
        ),
        ("maximum_work", options.settings.max_work.to_string()),
        ("timeout_ms", options.timeout_ms.to_string()),
        ("source_read_limits", source_limits(plan.source_limits())),
        (
            "archive_access",
            string("read_only_exact_selected_closures_without_writer_lock_or_recovery"),
        ),
        ("capture_time_label", string("unknown")),
        ("trusted_utc", "false".into()),
        ("packet_to_clock_correspondence_replayed", "false".into()),
        ("clock_equivalence_assumed", "false".into()),
        ("continuity_between_imports", "false".into()),
        ("absence_certifiable", "false".into()),
        (
            "gaps_mean",
            string("conditional_metadata_gaps_unknown_time_windows_may_overlap"),
        ),
        (
            "retention",
            string("selected_whole_windows_with_complete_native_original_proofs"),
        ),
        (
            "destination_contains_complete_catalog_or_clock",
            "false".into(),
        ),
        ("network", string("none")),
    ])
}
