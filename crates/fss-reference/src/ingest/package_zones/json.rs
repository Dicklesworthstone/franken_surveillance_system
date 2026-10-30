#![forbid(unsafe_code)]
//! Complete bounded operator projection; no ranked/truncated events or hidden missing samples.

mod screened;

use super::*;
use crate::ingest::package_detect::json_string as quote;

/// The operation actually completed by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageZoneOperation {
    /// Read-only analysis and exact retention proposal.
    Analyzed,
    /// This invocation committed the approved report.
    Retained,
    /// Exact committed retry, with no new cognition revision.
    AlreadyRetained,
    /// Selected cold report was completely source-rebuilt and matched.
    ReadVerified,
}
impl PackageZoneOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Analyzed => "analyzed",
            Self::Retained => "retained",
            Self::AlreadyRetained => "already_retained",
            Self::ReadVerified => "read_verified",
        }
    }
}
fn digest(d: ContentDigest) -> String {
    quote(&d.to_text())
}
fn anchor(a: &LedgerAnchor) -> String {
    format!(
        concat!(
            "{{\"site_lineage\":{},\"ledger_epoch\":{},\"commit_sequence\":{},",
            "\"adapter_registry_epoch\":{},\"schema_epoch\":{},\"policy_epoch\":{},\"privacy_epoch\":{},\"state_root\":{}}}"
        ),
        quote(&a.site_lineage),
        a.ledger_epoch,
        a.commit_sequence,
        a.adapter_registry_epoch,
        a.schema_epoch,
        a.policy_epoch,
        a.privacy_epoch,
        digest(a.state_root)
    )
}
fn optional<T: ToString>(value: Option<T>) -> String {
    value.map_or_else(|| "null".into(), |v| v.to_string())
}
fn duration(value: Option<u128>) -> String {
    value.map_or_else(|| "null".into(), |v| quote(&v.to_string()))
}
fn append(out: &mut String, value: &str) -> Result<()> {
    if out
        .len()
        .checked_add(value.len())
        .is_none_or(|n| n >= MAX_PACKAGE_ZONE_JSON_BYTES)
    {
        return Err(PackageZoneError::Limit);
    }
    out.push_str(value);
    Ok(())
}
fn render(
    report: &PackageZoneReport,
    operation: PackageZoneOperation,
    retained: Option<&LedgerAnchor>,
    admit_maximum_usage: bool,
) -> Result<String> {
    let r = report.analysis.retained().record();
    let tracking = report.analysis.config();
    let mut out = format!(
        concat!(
            "{{\"schema\":{},\"operation\":{},\"report_digest\":{},\"provenance_root\":{},",
            "\"configuration_digest\":{},\"approval_digest\":{},\"retained\":{},\"retention_anchor\":{},",
            "\"source\":{{\"site\":{},\"import_identity\":{},\"import_root\":{},\"package_report\":{},",
            "\"analysis_digest\":{},\"package_digest\":{},\"model_id\":{},\"generation\":{},",
            "\"contract_digest\":{},\"label\":{},\"class_index\":{},\"capture_time_label\":{},",
            "\"clock_basis\":{},\"privacy_binding\":{},\"source_anchor\":{}}},",
            "\"configuration\":{{\"confirmation_hits\":{},\"maximum_missed_frames\":{},\"minimum_iou_ppm\":{},",
            "\"maximum_sample_gap_ns\":{},\"dwell\":{},\"zones\":["
        ),
        quote(if report.health.is_some() {
            PACKAGE_ZONE_SCREENED_REPORT_DOMAIN
        } else {
            PACKAGE_ZONE_REPORT_DOMAIN
        }),
        quote(operation.as_str()),
        digest(report.digest),
        digest(report.provenance_root()),
        digest(ContentDigest::sha256(&wire::config_bytes(&report.config))),
        digest(report.approval),
        retained.is_some(),
        retained.map_or_else(|| "null".into(), anchor),
        quote(&report.site),
        digest(r.import_identity),
        digest(r.import_root),
        digest(r.report_digest),
        digest(report.analysis.digest()),
        digest(r.package_digest),
        quote(&r.model_id),
        quote(&r.generation),
        digest(r.contract_digest),
        quote(report.analysis.label()),
        report.analysis.class_index(),
        quote(&report.capture_time_label),
        quote(report.clock.as_str()),
        digest(report.privacy.digest()),
        anchor(report.analysis.retained().authority_anchor()),
        tracking.confirmation_hits,
        tracking.maximum_missed_frames,
        tracking.minimum_iou_ppm,
        report.config.maximum_sample_gap_ns,
        report.config.dwell.map_or_else(
            || "null".into(),
            |d| format!(
                "{{\"minimum_duration_ns\":{},\"minimum_observations\":{}}}",
                d.minimum_duration_ns, d.minimum_observations
            )
        )
    );
    for (index, z) in report.config.zones.iter().enumerate() {
        append(
            &mut out,
            &format!(
                "{}{{\"id\":{},\"x\":{},\"y\":{},\"width\":{},\"height\":{},\"margin\":{}}}",
                if index == 0 { "" } else { "," },
                quote(&z.id),
                z.x,
                z.y,
                z.width,
                z.height,
                z.margin
            ),
        )?;
    }
    append(&mut out, "]},\"frames\":[")?;
    for (index, f) in report.frames.iter().enumerate() {
        append(
            &mut out,
            &format!(
                concat!(
                    "{}{{\"segment\":{},\"capsule_digest\":{},",
                    "\"capture\":{{\"earliest_ns\":{},\"latest_ns\":{}}},\"dimensions\":[{},{}],",
                    "\"time_reliable\":{},\"source_boundary\":{}}}"
                ),
                if index == 0 { "" } else { "," },
                f.segment,
                digest(f.capsule_digest),
                quote(&f.capture.earliest.0.to_string()),
                quote(&f.capture.latest.0.to_string()),
                f.dimensions[0],
                f.dimensions[1],
                f.time_reliable,
                f.source_boundary
            ),
        )?;
    }
    append(&mut out, "],\"tracks\":[")?;
    for (index, t) in report.analysis.tracks().iter().enumerate() {
        append(
            &mut out,
            &format!(
                "{}{{\"identity\":{},\"track_id\":{},\"ever_confirmed\":{}}}",
                if index == 0 { "" } else { "," },
                digest(t.identity),
                t.track_id,
                t.confirmed
            ),
        )?;
    }
    append(&mut out, "],\"cells\":[")?;
    for (index, c) in report.cells.iter().enumerate() {
        let bounds = c.bounds.map_or_else(
            || "null".into(),
            |b| format!("[{},{},{},{}]", b[0], b[1], b[2], b[3]),
        );
        append(
            &mut out,
            &format!(
                concat!(
                    "{}{{\"track\":{},\"zone\":{},\"frame\":{},\"relation\":{},",
                    "\"sample_confirmed\":{},\"detection_row\":{},\"bounds\":{},\"clipped\":{}}}"
                ),
                if index == 0 { "" } else { "," },
                digest(c.track),
                quote(&report.config.zones[c.zone].id),
                c.frame,
                quote(c.relation.as_str()),
                c.sample_confirmed,
                optional(c.detection_row),
                bounds,
                c.clipped
            ),
        )?;
    }
    append(&mut out, "],\"events\":[")?;
    for (index, e) in report.events.iter().enumerate() {
        append(
            &mut out,
            &format!(
                concat!(
                    "{}{{\"kind\":{},\"track\":{},\"zone\":{},\"from_frame\":{},\"at_frame\":{},",
                    "\"through_frame\":{},\"observations\":{},\"minimum_duration_ns\":{},\"maximum_duration_ns\":{}}}"
                ),
                if index == 0 { "" } else { "," },
                quote(e.kind.as_str()),
                digest(e.track),
                quote(&report.config.zones[e.zone].id),
                optional(e.from_frame),
                e.at_frame,
                e.through_frame,
                e.observations,
                duration(e.minimum_duration_ns),
                duration(e.maximum_duration_ns)
            ),
        )?;
    }
    append(&mut out, "]")?;
    if let Some(health) = &report.health {
        screened::append_report(&mut out, health, admit_maximum_usage)?;
    }
    append(
        &mut out,
        &format!(
            concat!(
                ",\"semantics\":{{\"calibrated\":false,\"continuous_occupancy\":false,",
                "\"absence_authorized\":false,\"effects_authorized\":false,\"source_health_assessed\":{}}}}}\n"
            ),
            report.health.is_some()
        ),
    )?;
    Ok(out)
}
impl PackageZoneReport {
    /// Complete bounded JSON; a retained/read status requires an actual retained receipt.
    pub fn to_json(&self, operation: PackageZoneOperation) -> Result<String> {
        if self
            .health
            .as_ref()
            .is_some_and(health::Screening::delivery_blocked)
        {
            return Err(PackageZoneError::Mismatch);
        }
        if operation != PackageZoneOperation::Analyzed && self.retention.is_none() {
            return Err(PackageZoneError::Unavailable);
        }
        render(self, operation, self.retention.as_ref(), false)
    }
    /// Admit the largest post-retention receipt before writing any retained state. This only
    /// checks output capacity; its hypothetical anchor is never returned as a real result.
    pub fn admit_retention_json(&self) -> Result<()> {
        let mut maximum = self.analysis.retained().authority_anchor().clone();
        maximum.ledger_epoch = u64::MAX;
        maximum.commit_sequence = u64::MAX;
        maximum.adapter_registry_epoch = u64::MAX;
        maximum.schema_epoch = u64::MAX;
        maximum.policy_epoch = u64::MAX;
        maximum.privacy_epoch = u64::MAX;
        render(
            self,
            PackageZoneOperation::AlreadyRetained,
            Some(&maximum),
            true,
        )?;
        Ok(())
    }
}
