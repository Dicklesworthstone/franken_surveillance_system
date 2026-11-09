#![forbid(unsafe_code)]
//! Pure JSON projection of the complete vendor-zone contract, with no raw vendor values.

use std::fmt::{self, Write};

use fss_cli::json_output::string;
use fss_reference::onvif::metadata::zones::contract::{
    COORDINATE_SCALE, ZONE_COORDINATES, ZONE_GENERATION, ZONE_POLICY_SCHEMA, ZONE_REPORT_DOMAIN,
    ZoneReport, ZoneUnavailable,
};

fn reason(value: Option<ZoneUnavailable>) -> String {
    value.map_or_else(|| "null".to_owned(), |value| string(value.as_str()))
}

/// Write one complete JSON value; the retained CLI owner supplies the bounded output sink.
/// All source handles remain indices into the accompanying verified tracklet inventory.
pub(super) fn write_json(out: &mut impl Write, report: &ZoneReport) -> fmt::Result {
    write!(
        out,
        "{{\"schema\":{},\"generation\":{},\"coordinates\":{},\"coordinate_scale\":{},\"plane\":\"cognition\",\"provenance\":\"derived\",\"source_provenance\":\"vendor_claimed\",\"calibrated\":false,\"absence_certified\":false,\"physical_identity\":false,\"effect_authority\":false,\"policy_digest\":{},\"tracklet_report_digest\":{},\"input_digest\":{},\"report_digest\":{},\"policy\":{{\"schema\":{},\"coordinates\":{},\"zones\":[",
        string(ZONE_REPORT_DOMAIN),
        string(ZONE_GENERATION),
        string(ZONE_COORDINATES),
        COORDINATE_SCALE,
        string(&report.policy_digest.to_text()),
        string(&report.tracklet_report_digest.to_text()),
        string(&report.input_digest.to_text()),
        string(&report.report_digest.to_text()),
        string(ZONE_POLICY_SCHEMA),
        string(ZONE_COORDINATES)
    )?;
    for (index, zone) in report.policy.zones.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"id\":{},\"scope\":{},\"module_digest\":{},\"frame_transform_digest\":{},\"object_transform_digest\":{},\"min\":[{},{}],\"max\":[{},{}],\"margin\":{}}}",
            string(&zone.id),
            string(&zone.scope.to_text()),
            string(&zone.module_digest.to_text()),
            string(&zone.frame_transform_digest.to_text()),
            string(&zone.object_transform_digest.to_text()),
            zone.min[0],
            zone.min[1],
            zone.max[0],
            zone.max[1],
            zone.margin
        )?;
    }
    let limits = report.limits;
    write!(
        out,
        "]}},\"limits\":{{\"max_cells\":{},\"max_frame_samples\":{},\"max_transitions\":{},\"max_work_units\":{},\"max_output_bytes\":{}}},\"cells\":[",
        limits.max_cells,
        limits.max_frame_samples,
        limits.max_transitions,
        limits.max_work_units,
        limits.max_output_bytes
    )?;
    for (index, cell) in report.cells.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"zone_index\":{},\"occurrence_index\":{},\"frame_ordinal\":{},\"relation\":{},\"reason\":{}}}",
            cell.zone_index,
            cell.occurrence_index,
            cell.frame_ordinal,
            string(cell.relation.as_str()),
            reason(cell.reason)
        )?;
    }
    out.write_str("],\"frame_samples\":[")?;
    for (index, sample) in report.frame_samples.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        write!(
            out,
            "{{\"zone_index\":{},\"frame_ordinal\":{},\"basis_unavailable\":{},\"inside\":{},\"outside\":{},\"boundary\":{},\"unavailable\":{}}}",
            sample.zone_index,
            sample.frame_ordinal,
            reason(sample.basis_unavailable),
            sample.inside,
            sample.outside,
            sample.boundary,
            sample.unavailable
        )?;
    }
    out.write_str("],\"transitions\":[")?;
    for (index, transition) in report.transitions.iter().enumerate() {
        if index != 0 {
            out.write_char(',')?;
        }
        let previous = transition
            .previous_occurrence
            .map_or_else(|| "null".to_owned(), |value| value.to_string());
        write!(
            out,
            "{{\"zone_index\":{},\"tracklet_identity\":{},\"kind\":{},\"previous_occurrence\":{},\"occurrence\":{}}}",
            transition.zone_index,
            string(&transition.tracklet_identity.to_text()),
            string(transition.kind.as_str()),
            previous,
            transition.occurrence
        )?;
    }
    write!(
        out,
        "],\"work_units\":{},\"encoded_bytes\":{}}}",
        report.work_units, report.encoded_bytes
    )
}
