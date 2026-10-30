#![forbid(unsafe_code)]
//! Historical screening projection, separate from frozen canonical identity.

use super::*;

pub(super) fn append_report(
    out: &mut String,
    health: &health::Screening,
    admit_maximum_usage: bool,
) -> Result<()> {
    append(
        out,
        concat!(
            ",\"historical_health\":{\"policy\":\"require_complete_matching_finite_screen_without_findings\",",
            "\"historical_only\":true,\"current_camera_health_established\":false,",
            "\"physical_cause_established\":false,\"absence_certified\":false,",
            "\"native_trace_replayed\":false,\"frames\":["
        ),
    )?;
    for (index, exposure) in health.exposures.iter().enumerate() {
        let source = exposure.source();
        append(
            out,
            &format!(
                concat!(
                    "{}{{\"frame\":{},\"state\":{},\"zone_support_allowed\":{},",
                    "\"screening_incomplete\":{},\"source_import\":{},\"import_root\":{},",
                    "\"sensor_id\":{},\"segment\":{},\"privacy_policy_digest\":{},",
                    "\"privacy_generation\":{},\"diagnostics\":["
                ),
                if index == 0 { "" } else { "," },
                index,
                quote(exposure.status()),
                health::support_allowed(exposure),
                exposure.screening_incomplete(),
                digest(source.import_identity),
                digest(source.import_root),
                quote(source.sensor_id.as_str()),
                source.segment,
                source
                    .privacy_policy_digest
                    .map_or_else(|| "null".into(), digest),
                optional(source.privacy_generation),
            ),
        )?;
        for (pin_index, pin) in exposure.pins().iter().enumerate() {
            append(
                out,
                &format!(
                    "{}{{\"record_digest\":{},\"provenance_root\":{},\"trace_digest\":{},\"publication_anchor\":{}}}",
                    if pin_index == 0 { "" } else { "," },
                    digest(pin.record_digest),
                    digest(pin.provenance_root),
                    digest(pin.trace_digest),
                    anchor(&pin.ledger_anchor),
                ),
            )?;
        }
        append(out, "],\"findings\":[")?;
        for (finding_index, finding) in exposure.findings().iter().enumerate() {
            append(
                out,
                &format!(
                    concat!(
                        "{}{{\"diagnostic\":{},\"provenance_root\":{},\"finding\":{},",
                        "\"finding_first_segment\":{},\"finding_last_segment\":{},",
                        "\"withheld_first_segment\":{},\"withheld_last_segment\":{}}}"
                    ),
                    if finding_index == 0 { "" } else { "," },
                    digest(finding.diagnostic),
                    digest(finding.provenance_root),
                    quote(finding.finding.as_str()),
                    finding.finding_first_segment,
                    finding.finding_last_segment,
                    finding.withheld_first_segment,
                    finding.withheld_last_segment,
                ),
            )?;
        }
        append(out, "]}")?;
    }
    // Reserve the largest numeric projection before retention. Hypothetical values never
    // become report identity or returned usage; ordinary rendering reports actual reservations.
    let admit = |value: u64| if admit_maximum_usage { u64::MAX } else { value };
    let usage = health.usage;
    append(
        out,
        &format!(
            concat!(
                "],\"operation_usage\":{{\"catalog_loads\":{},\"records_seen\":{},",
                "\"records_loaded\":{},\"deleted_records\":{},\"metadata_bytes_read\":{},",
                "\"metadata_reads\":{},\"history_work_admitted\":{},\"assessment_work\":{},",
                "\"findings_returned\":{},\"diagnostic_trace_bytes_verified\":{},\"diagnostic_trace_reads\":{},",
                "\"retention_indexed_read_bytes_reserved\":{},\"retention_indexed_read_attempts\":{},",
                "\"retention_indexed_read_byte_limit\":{},\"retention_indexed_read_attempt_limit\":{},",
                "\"included_in_report_digest\":false}}}}"
            ),
            admit(health.loads as u64),
            admit(usage.records_seen as u64),
            admit(usage.records_loaded as u64),
            admit(usage.deleted_records as u64),
            admit(usage.metadata_bytes_read as u64),
            admit(usage.metadata_reads as u64),
            admit(usage.history_work_admitted as u64),
            admit(usage.assessment_work as u64),
            admit(usage.findings_returned as u64),
            admit(health.trace_bytes_verified as u64),
            admit(health.trace_reads as u64),
            admit(health.retention_read_bytes_reserved),
            admit(health.retention_read_attempts),
            health::MAX_RETENTION_READ_BYTES,
            health::MAX_RETENTION_READ_ATTEMPTS,
        ),
    )?;
    Ok(())
}
