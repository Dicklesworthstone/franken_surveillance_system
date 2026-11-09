#![forbid(unsafe_code)]
//! Exact JSON for a complete lifecycle projection; the enclosing owner supplies custody.

use std::fmt::{self, Write};

use fss_core::ContentDigest;
use fss_reference::onvif::metadata::lifecycle::contract::{
    LIFECYCLE_GENERATION, LifecycleEndpoint, LifecycleIssue, LifecycleOccurrenceRef,
    LifecycleReport,
};
use fss_reference::onvif::wire::LifecycleReference;

fn string(value: &str) -> String {
    fss_cli::json_output::string(value)
}
fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn optional_text(value: Option<&str>) -> String {
    value.map_or_else(|| "null".into(), string)
}
fn optional_index(value: Option<usize>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}
fn issues(values: &[LifecycleIssue]) -> String {
    fss_cli::json_output::strings(values.iter().map(|value| value.as_str()))
}

fn reference(
    out: &mut impl Write,
    value: &LifecycleReference,
    include_values: bool,
) -> fmt::Result {
    write!(
        out,
        "{{\"integer_present\":{},\"uuid_present\":{},\"unsupported_extensions\":{},\"values\":",
        value.object_id.is_some(),
        value.uuid.is_some(),
        value.unsupported_extensions
    )?;
    if include_values {
        // UUID values are unsupported, never matched and never disclosed by this surface.
        write!(
            out,
            "{{\"object_id\":{}}}",
            optional_text(value.object_id.as_deref())
        )?;
    } else {
        out.write_str("null")?;
    }
    out.write_char('}')
}

fn occurrence(out: &mut impl Write, value: &LifecycleOccurrenceRef) -> fmt::Result {
    write!(
        out,
        "{{\"basis\":{},\"occurrence_ordinal\":{},\"occurrence_identity\":{},\"tracklet_identity\":{},\"frame_ordinal\":{},\"object_index\":{}}}",
        string(value.basis.as_str()),
        value.occurrence_ordinal,
        digest(value.occurrence_identity),
        digest(value.tracklet_identity),
        value.frame_ordinal,
        value.object_index
    )
}

fn endpoints(
    out: &mut impl Write,
    values: &[LifecycleEndpoint],
    include_values: bool,
) -> fmt::Result {
    out.write_char('[')?;
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        out.write_str("{\"reference\":")?;
        reference(out, &value.reference, include_values)?;
        write!(
            out,
            ",\"state\":{},\"issues\":{},\"observations\":[",
            string(value.state.as_str()),
            issues(&value.issues)
        )?;
        for (position, observation) in value.observations.iter().enumerate() {
            if position != 0 {
                out.write_char(',')?;
            }
            occurrence(out, observation)?;
        }
        out.write_str("]}")?;
    }
    out.write_char(']')
}

/// Write one complete JSON object. The caller supplies a bounded, admission-aware writer and
/// releases output only after this succeeds. Raw integer/module/time values require explicit
/// opt-in; UUIDs appear only as presence flags under both disclosure modes.
pub(super) fn write_json(
    out: &mut impl Write,
    report: &LifecycleReport,
    include_values: bool,
) -> fmt::Result {
    let limits = report.limits;
    write!(
        out,
        "{{\"generation\":{},\"report_digest\":{},\"policy_digest\":{},\"input_digest\":{},\"tracklet_report_digest\":{},\"work_units\":{},\"encoded_bytes\":{},\"limits\":{{\"max_frames\":{},\"max_objects\":{},\"max_operations\":{},\"max_references\":{},\"max_work_units\":{},\"max_output_bytes\":{}}},\"frames\":[",
        string(LIFECYCLE_GENERATION),
        digest(report.report_digest),
        digest(report.policy_digest),
        digest(report.input_digest),
        digest(report.tracklet_report_digest),
        report.work_units,
        report.encoded_bytes,
        limits.max_frames,
        limits.max_objects,
        limits.max_operations,
        limits.max_references,
        limits.max_work_units,
        limits.max_output_bytes
    )?;
    for (index, frame) in report.frames.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        let source = &frame.reference;
        write!(
            out,
            "{{\"ordinal\":{},\"scope\":{},\"source_identity\":{},\"source_root\":{},\"source_digest\":{},\"frame_digest\":{},\"document_index\":{},\"frame_index\":{},\"section_index\":{},\"section_child_index\":{},\"object_tree_child_index\":{},\"occurrence_start\":{},\"occurrence_count\":{},\"operation_start\":{},\"operation_count\":{},\"behaviour_start\":{},\"behaviour_count\":{},\"barriers\":{},\"values\":",
            source.ordinal,
            digest(source.scope),
            digest(source.source_identity),
            digest(source.source_root),
            digest(source.source_digest),
            digest(source.frame_digest),
            source.document_index,
            source.frame_index,
            frame.section_index,
            frame.section_child_index,
            optional_index(frame.object_tree_child_index),
            frame.occurrence_start,
            frame.occurrence_count,
            frame.operation_start,
            frame.operation_count,
            frame.behaviour_start,
            frame.behaviour_count,
            fss_cli::json_output::strings(frame.barriers.iter().map(|value| value.as_str()))
        )?;
        if include_values {
            write!(
                out,
                "{{\"module_source\":{},\"vendor_utc_time\":{}}}",
                optional_text(frame.module_source.as_deref()),
                string(&frame.vendor_utc_time)
            )?;
        } else {
            out.write_str("null")?;
        }
        out.write_char('}')?;
    }
    out.write_str("],\"operations\":[")?;
    for (index, operation) in report.operations.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"identity\":{},\"frame_ordinal\":{},\"operation_index\":{},\"tree_child_index\":{},\"kind\":{},\"state\":{},\"unsupported_extensions\":{},\"from\":",
            digest(operation.identity),
            operation.frame_ordinal,
            operation.operation_index,
            operation.tree_child_index,
            string(operation.kind.as_str()),
            string(operation.state.as_str()),
            operation.unsupported_extensions
        )?;
        endpoints(out, &operation.from, include_values)?;
        out.write_str(",\"to\":")?;
        endpoints(out, &operation.to, include_values)?;
        out.write_char('}')?;
    }
    out.write_str("],\"behaviours\":[")?;
    for (index, behaviour) in report.behaviours.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"identity\":{},\"occurrence\":",
            digest(behaviour.identity)
        )?;
        occurrence(out, &behaviour.occurrence)?;
        write!(
            out,
            ",\"frame_child_index\":{},\"reference\":",
            behaviour.frame_child_index
        )?;
        reference(out, &behaviour.reference, include_values)?;
        write!(
            out,
            ",\"idle\":{},\"removed\":{},\"unsupported_extensions\":{},\"state\":{},\"issues\":{}}}",
            behaviour.idle,
            behaviour.removed,
            behaviour.unsupported_extensions,
            string(behaviour.state.as_str()),
            issues(&behaviour.issues)
        )?;
    }
    out.write_str("],\"reuses\":[")?;
    for (index, reuse) in report.reuses.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"identity\":{},\"deleted_by_operation\":{},\"deleted_at_frame\":{},\"occurrence\":",
            digest(reuse.identity),
            digest(reuse.deleted_by_operation),
            reuse.deleted_at_frame
        )?;
        occurrence(out, &reuse.occurrence)?;
        out.write_char('}')?;
    }
    out.write_str("]}")
}
