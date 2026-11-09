#![forbid(unsafe_code)]
//! Reusable closed JSON presentation of a completed retained vendor-tracklet snapshot.
//! This module performs no I/O, source reading, authority creation, publication or grouping.

#[path = "report/projection.rs"]
mod projection;

use std::fmt::{self, Write};

use fss_core::{CanonicalEncode, ContentDigest};
use fss_reference::onvif::metadata::tracks::{RetainedTracklets, contract::TRACKLET_GENERATION};

/// Hard complete JSON byte bound, independent of the canonical projection's byte ceiling.
pub(crate) const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
/// Closed report schema; all raw vendor fields are explicitly null by default.
pub(crate) const SCHEMA: &str = "fss.onvif_vendor_tracklets_report.v1";
const LIMIT: &str = "ERR-ONVIF-TRACKLETS-JSON-LIMIT-001";

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
/// Emit a complete, bounded snapshot; an error releases no valid prefix. Exact timestamps and
/// raw module/ObjectId spellings require include_values, just like the existing inspect lane.
pub(crate) fn render(
    retained: &RetainedTracklets,
    include_values: bool,
) -> Result<String, &'static str> {
    let mut out = Bounded {
        text: String::new(),
    };
    write_report(&mut out, retained, include_values).map_err(|_| LIMIT)?;
    Ok(out.text)
}

fn write_report(
    out: &mut Bounded,
    retained: &RetainedTracklets,
    include_values: bool,
) -> fmt::Result {
    let report = retained.report();
    let limits = retained.limits();
    let usage = retained.usage();
    let anchor = retained.authority_anchor();
    write!(
        out,
        "{{\"schema\":{},\"status\":\"verified\",\"plane\":\"cognition\",\"provenance\":\"derived\",\"source_provenance\":\"vendor_claimed\",\"tracklet_generation\":{},\"vendor_values_included\":{},\"snapshot_digest\":{},\"report_digest\":{},\"input_digest\":{},\"policy_digest\":{},\"authority\":{{\"anchor_digest\":{},\"commit_sequence\":{}}},",
        string(SCHEMA),
        string(TRACKLET_GENERATION),
        include_values,
        digest(retained.digest()),
        digest(report.report_digest),
        digest(report.input_digest),
        digest(report.policy_digest),
        digest(ContentDigest::sha256(&anchor.canonical_bytes())),
        anchor.commit_sequence
    )?;
    write!(
        out,
        "\"limits\":{{\"max_sources\":{},\"max_stored_bytes\":{},\"max_indexed_reads\":{},\"max_work_units\":{},\"max_frames\":{},\"max_objects\":{},\"max_tracklets\":{},\"max_projection_work_units\":{},\"max_projection_bytes\":{},\"max_vendor_gap_ns\":{},\"max_json_bytes\":{}}},",
        limits.max_sources,
        limits.max_stored_bytes,
        limits.max_indexed_reads,
        limits.max_work_units,
        limits.projection.max_frames,
        limits.projection.max_objects,
        limits.projection.max_tracklets,
        limits.projection.max_work_units,
        limits.projection.max_output_bytes,
        limits.projection.max_vendor_gap_ns,
        MAX_JSON_BYTES
    )?;
    write!(
        out,
        "\"usage\":{{\"source_validation_passes\":2,\"indexed_read_bytes\":{},\"indexed_read_attempts\":{},\"reserved_work_units\":{},\"projection_work_units_per_pass\":{},\"projection_bytes\":{},\"opening_recovery_included\":false}},\"sources\":[",
        usage.indexed_reads.used_bytes,
        usage.indexed_reads.used_read_attempts,
        usage.reserved_work_units,
        report.work_units,
        report.encoded_bytes
    )?;
    for (index, source) in retained.sources().iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"index\":{},\"kind\":{},\"identity\":{},\"root\":{},\"scope\":{},\"source_digest\":{},\"native_source_digest\":{},\"interpretation_digest\":{},\"parser_generation\":{},\"source_mode\":{},\"publication_anchor_digest\":{},\"documents\":{},\"analytics_frames\":{},\"empty_analytics_documents\":{},\"rejected_documents\":{},\"uninterpreted_documents\":{},\"source_processing_complete\":{}}}",
            index,
            string(source.pin.kind()),
            digest(source.pin.identity()),
            digest(source.pin.root()),
            digest(source.scope),
            digest(source.source_digest),
            optional_digest(source.native_source_digest),
            digest(source.interpretation_digest),
            string(source.parser_generation),
            string(source.source_mode),
            digest(ContentDigest::sha256(
                &source.publication_anchor.canonical_bytes()
            )),
            source.documents,
            source.analytics_frames,
            source.empty_analytics_documents,
            source.rejected_documents,
            source.uninterpreted_documents,
            source.source_processing_complete
        )?;
    }
    out.write_str("],")?;
    projection::write_projection(out, report, include_values)?;
    out.write_str(",\"claims\":{\"physical_identity\":false,\"authenticated_origin\":false,\"coverage\":false,\"physical_absence\":false,\"calibrated_geometry\":false,\"event_authority\":false,\"effect_permission\":false}}\n")
}
