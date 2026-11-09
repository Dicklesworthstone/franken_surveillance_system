#![forbid(unsafe_code)]
//! Complete bounded JSON envelope for a source-verified lifecycle query.
//! This presentation layer has no I/O, source ownership, matching or effect authority.

use std::fmt::{self, Write};

use fss_core::ContentDigest;
use fss_reference::onvif::metadata::lifecycle::RetainedLifecycle;
use fss_reference::onvif::wire::{EventDocumentFormat, LIFECYCLE_PARSER_GENERATION};

use super::super::tracks;
use super::lifecycle_json;

/// Complete JSON byte ceiling, separately from the canonical projection ceiling.
pub(super) const MAX_JSON_BYTES: usize = 32 * 1024 * 1024;
/// Closed source-verified lifecycle query envelope.
pub(super) const SCHEMA: &str = "fss.onvif_vendor_lifecycle_report.v1";
const LIMIT: &str = "ERR-ONVIF-LIFECYCLE-JSON-LIMIT-001";

struct Bounded {
    text: String,
}
impl Write for Bounded {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let total = self.text.len().checked_add(value.len()).ok_or(fmt::Error)?;
        if total > MAX_JSON_BYTES {
            return Err(fmt::Error);
        }
        self.text.try_reserve(value.len()).map_err(|_| fmt::Error)?;
        self.text.push_str(value);
        Ok(())
    }
}
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
fn optional_index(value: Option<usize>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

/// A formatting/allocation refusal releases no successful JSON prefix. Original vendor
/// values are controlled by the same disclosure flag in the nested tracklet and lineage rows.
pub(super) fn render(
    retained: &RetainedLifecycle,
    include_values: bool,
) -> Result<String, &'static str> {
    let original = tracks::report::render(retained.snapshot(), include_values)?;
    let mut out = Bounded {
        text: String::new(),
    };
    write_report(&mut out, retained, include_values, &original).map_err(|_| LIMIT)?;
    Ok(out.text)
}

fn write_report(
    out: &mut Bounded,
    retained: &RetainedLifecycle,
    include_values: bool,
    original: &str,
) -> fmt::Result {
    let parse = retained.limits().parse;
    write!(
        out,
        "{{\"schema\":{},\"status\":\"verified\",\"plane\":\"cognition\",\"provenance\":\"derived\",\"source_provenance\":\"vendor_claimed\",\"parser_generation\":{},\"vendor_values_included\":{},\"snapshot_digest\":{},\"max_json_bytes\":{},\"parser_limits\":{{\"max_frames\":{},\"max_objects\":{},\"max_operations\":{},\"max_references\":{},\"max_work_units\":{}}},\"tracklets\":",
        string(SCHEMA),
        string(LIFECYCLE_PARSER_GENERATION),
        include_values,
        digest(retained.digest()),
        MAX_JSON_BYTES,
        parse.max_frames,
        parse.max_objects,
        parse.max_operations,
        parse.max_references,
        parse.max_work_units
    )?;
    // The original report is already a complete bounded JSON value. Its trailing newline is
    // ordinary JSON whitespace and is deliberately preserved when embedding the exact report.
    out.write_str(original)?;
    out.write_str(",\"documents\":[")?;
    for (index, document) in retained.documents().iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        let format = document.format.map(|value| match value {
            EventDocumentFormat::PullMessages => "pull_messages",
            EventDocumentFormat::MetadataStream => "metadata_stream",
        });
        write!(
            out,
            "{{\"source_ordinal\":{},\"source_kind\":{},\"source_identity\":{},\"source_root\":{},\"document_index\":{},\"source_digest\":{},\"source_bytes\":{},\"parser_generation\":{},\"format\":{},\"state\":{},\"original_parse_error\":{},\"frame_start\":{},\"frames\":{},\"objects\":{},\"operations\":{},\"references\":{},\"unsupported_sections\":{},\"uninterpreted_frames\":{},\"parse_work_units\":{}}}",
            document.source_ordinal,
            string(document.pin.kind()),
            digest(document.pin.identity()),
            digest(document.pin.root()),
            optional_index(document.document_index),
            optional_digest(document.source_digest),
            document.source_bytes,
            string(document.parser_generation),
            optional_text(format),
            string(document.state.as_str()),
            optional_text(document.original_parse_error),
            document.frame_start,
            document.frames,
            document.objects,
            document.operations,
            document.references,
            document.unsupported_sections,
            document.uninterpreted_frames,
            document.parse_work_units
        )?;
    }
    out.write_str("],\"analysis\":")?;
    lifecycle_json::write_json(out, retained.report(), include_values)?;
    out.write_str(",\"claims\":{\"physical_identity\":false,\"physical_departure\":false,\"authenticated_origin\":false,\"coverage\":false,\"physical_absence\":false,\"calibrated_geometry\":false,\"event_authority\":false,\"effect_permission\":false}}\n")
}
