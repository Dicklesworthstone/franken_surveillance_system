#![forbid(unsafe_code)]
//! Exact JSON arrays for a pure vendor-tracklet projection. This function grants no custody.

use fss_core::ContentDigest;
use fss_reference::onvif::metadata::tracks::contract::TrackletReport;
use std::fmt::{self, Write};

fn string(value: &str) -> String {
    fss_cli::json_output::string(value)
}
fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn optional_digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".into(), digest)
}
fn optional_text(value: Option<&str>) -> String {
    value.map_or_else(|| "null".into(), string)
}
fn reasons(
    values: &[fss_reference::onvif::metadata::tracks::contract::TrackBreakReason],
) -> String {
    fss_cli::json_output::strings(values.iter().map(|reason| reason.as_str()))
}

/// Write the three complete projection arrays without outer braces or a trailing comma.
/// The caller owns the finite output writer and is responsible for current source custody.
pub(crate) fn write_projection(
    out: &mut impl Write,
    report: &TrackletReport,
    include_values: bool,
) -> fmt::Result {
    out.write_str("\"frames\":[")?;
    for (index, frame) in report.frames.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        let reference = &frame.reference;
        write!(
            out,
            "{{\"ordinal\":{},\"scope\":{},\"source_identity\":{},\"source_root\":{},\"source_digest\":{},\"frame_digest\":{},\"document_index\":{},\"frame_index\":{},\"module_digest\":{},\"transformation_digest\":{},\"occurrence_start\":{},\"occurrence_count\":{},\"barriers\":{},\"values\":",
            reference.ordinal,
            digest(reference.scope),
            digest(reference.source_identity),
            digest(reference.source_root),
            digest(reference.source_digest),
            digest(reference.frame_digest),
            reference.document_index,
            reference.frame_index,
            optional_digest(frame.module_digest),
            digest(frame.transformation_digest),
            frame.occurrence_start,
            frame.occurrence_count,
            reasons(&frame.barriers)
        )?;
        if include_values {
            write!(
                out,
                "{{\"module_source\":{},\"vendor_utc_time\":{},\"vendor_time_ns\":{}}}",
                optional_text(frame.module_source.as_deref()),
                string(&frame.vendor_utc_time),
                string(&frame.vendor_time_ns.to_string())
            )?;
        } else {
            out.write_str("null")?;
        }
        out.write_char('}')?;
    }
    out.write_str("],\"occurrences\":[")?;
    for (index, occurrence) in report.occurrences.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"identity\":{},\"tracklet_identity\":{},\"frame_ordinal\":{},\"object_index\":{},\"transformation_digest\":{},\"values\":",
            digest(occurrence.identity),
            digest(occurrence.tracklet_identity),
            occurrence.frame_ordinal,
            occurrence.object_index,
            digest(occurrence.transformation_digest)
        )?;
        if include_values {
            write!(
                out,
                "{{\"vendor_object_id\":{},\"module_source\":{},\"vendor_utc_time\":{}}}",
                string(&occurrence.vendor_object_id),
                optional_text(occurrence.module_source.as_deref()),
                string(&occurrence.vendor_utc_time)
            )?;
        } else {
            out.write_str("null")?;
        }
        out.write_char('}')?;
    }
    out.write_str("],\"tracklets\":[")?;
    for (index, tracklet) in report.tracklets.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"identity\":{},\"scope\":{},\"module_digest\":{},\"vendor_key_digest\":{},\"occurrence_indices\":[",
            digest(tracklet.identity),
            digest(tracklet.scope),
            optional_digest(tracklet.module_digest),
            digest(tracklet.vendor_key_digest)
        )?;
        for (at, occurrence) in tracklet.occurrence_indices.iter().enumerate() {
            if at != 0 {
                out.write_char(',')?;
            }
            write!(out, "{occurrence}")?;
        }
        write!(
            out,
            "],\"start_reasons\":{},\"end_reasons\":{}}}",
            reasons(&tracklet.start_reasons),
            reasons(&tracklet.end_reasons)
        )?;
    }
    out.write_char(']')
}
