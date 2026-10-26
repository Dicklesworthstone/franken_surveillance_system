#![forbid(unsafe_code)]
//! Source-bound historical diagnostic constraints shared by native supervision paths.

use std::collections::BTreeMap;

use fss_core::{ContentDigest, SensorId};
use fss_reference::ingest::historical_health::exposure::{
    HealthDiagnosticPin, HealthExposure, HealthExposureCatalog, HealthExposureLimits,
    HealthExposureSource,
};
use fss_reference::ingest::package_event::{
    PackageDetectionRecord, PackageEventError, RecordFrame,
};
use fss_reference::ingest::privacy_mask::{MaskBinding, current_mask};
use fss_reference::{ReferenceDeployment, ReplayCx};

use crate::agent_json::{array, evidence_anchor, object, string};

use super::{
    Error, MAX_RETAINED_SUPERVISOR_CAMERAS, Result, RetainedSupervisorLimits, checkpoint,
    package_error,
};

/// One bounded diagnostic snapshot and sensor-mask cache for an entire native operation.
#[derive(Debug)]
pub(super) struct HealthGuard {
    catalog: HealthExposureCatalog,
    masks: BTreeMap<SensorId, MaskBinding>,
}

impl HealthGuard {
    pub(super) fn read(
        deployment: &ReferenceDeployment,
        limits: &RetainedSupervisorLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        let defaults = HealthExposureLimits::default();
        let limits = HealthExposureLimits {
            maximum_metadata_bytes: defaults
                .maximum_metadata_bytes
                .min(limits.max_read_bytes as usize),
            maximum_metadata_reads: defaults
                .maximum_metadata_reads
                .min(limits.max_read_attempts as usize),
            ..defaults
        };
        let catalog = HealthExposureCatalog::read(deployment, limits, cx)
            .map_err(|error| Error::Health(Box::new(error)))?;
        Ok(Self {
            catalog,
            masks: BTreeMap::new(),
        })
    }

    pub(super) fn assess(
        &mut self,
        record: &PackageDetectionRecord,
        frame: &RecordFrame,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<HealthExposure> {
        checkpoint(cx)?;
        if self.catalog.anchor() != deployment.current_anchor() {
            return Err(Error::Authority);
        }
        let sensor = SensorId::parse(&frame.sensor_id)
            .map_err(|_| Error::Selection("native health sensor identity"))?;
        if !self.masks.contains_key(&sensor) {
            if self.masks.len() >= MAX_RETAINED_SUPERVISOR_CAMERAS {
                return Err(Error::Limit("native health camera bindings"));
            }
            let mask = current_mask(deployment, &sensor)
                .map_err(|error| package_error(PackageEventError::from(error)))?;
            self.masks.insert(sensor.clone(), mask);
        }
        let mask = self
            .masks
            .get(&sensor)
            .ok_or(Error::Selection("native health privacy binding"))?;
        self.catalog
            .assess(
                &HealthExposureSource {
                    import_identity: record.import_identity,
                    import_root: record.import_root,
                    sensor_id: sensor,
                    segment: frame.segment,
                    privacy_policy_digest: mask.policy_digest(),
                    privacy_generation: mask.generation(),
                },
                cx,
            )
            .map_err(|error| Error::Health(Box::new(error)))
    }

    pub(super) fn to_json(&self) -> String {
        let usage = self.catalog.usage();
        object(&[
            (
                "basis",
                string("source_bound_retained_finite_visual_diagnostics"),
            ),
            ("records_seen", usage.records_seen.to_string()),
            ("records_loaded", usage.records_loaded.to_string()),
            ("deleted_records", usage.deleted_records.to_string()),
            ("metadata_bytes_read", usage.metadata_bytes_read.to_string()),
            ("metadata_reads", usage.metadata_reads.to_string()),
            (
                "history_work_admitted",
                usage.history_work_admitted.to_string(),
            ),
            ("assessment_work", usage.assessment_work.to_string()),
            ("findings_returned", usage.findings_returned.to_string()),
            ("native_trace_replayed", "false".to_owned()),
            ("current_camera_health_established", "false".to_owned()),
            ("physical_cause_established", "false".to_owned()),
            ("absence_certified", "false".to_owned()),
        ])
    }
}

fn digest(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn optional_digest(value: Option<ContentDigest>) -> String {
    value.map_or_else(|| "null".to_owned(), digest)
}
fn pin_json(pin: &HealthDiagnosticPin) -> String {
    object(&[
        ("record_digest", digest(pin.record_digest)),
        ("provenance_root", digest(pin.provenance_root)),
        ("trace_digest", digest(pin.trace_digest)),
        ("publication_anchor", evidence_anchor(&pin.ledger_anchor)),
    ])
}

/// Stable complete exposure projection; excludes fresh operation roots and work counters so
/// unrelated later history does not alter the historical source's diagnostic interpretation.
pub(super) fn exposure_json(exposure: &HealthExposure) -> String {
    let source = exposure.source();
    object(&[
        ("state", string(exposure.status())),
        ("support_withheld", exposure.support_withheld().to_string()),
        (
            "screening_incomplete",
            exposure.screening_incomplete().to_string(),
        ),
        ("source_import", digest(source.import_identity)),
        ("import_root", digest(source.import_root)),
        ("sensor_id", string(source.sensor_id.as_str())),
        ("segment", source.segment.to_string()),
        (
            "privacy_policy_digest",
            optional_digest(source.privacy_policy_digest),
        ),
        (
            "privacy_generation",
            source
                .privacy_generation
                .map_or_else(|| "null".to_owned(), |n| n.to_string()),
        ),
        (
            "diagnostics",
            array(&exposure.pins().iter().map(pin_json).collect::<Vec<_>>()),
        ),
        (
            "reasons",
            array(
                &exposure
                    .reasons()
                    .into_iter()
                    .map(string)
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "findings",
            array(
                &exposure
                    .findings()
                    .iter()
                    .map(|finding| {
                        object(&[
                            ("diagnostic", digest(finding.diagnostic)),
                            ("provenance_root", digest(finding.provenance_root)),
                            ("finding", string(finding.finding.as_str())),
                            (
                                "finding_first_segment",
                                finding.finding_first_segment.to_string(),
                            ),
                            (
                                "finding_last_segment",
                                finding.finding_last_segment.to_string(),
                            ),
                            (
                                "withheld_first_segment",
                                finding.withheld_first_segment.to_string(),
                            ),
                            (
                                "withheld_last_segment",
                                finding.withheld_last_segment.to_string(),
                            ),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
        ("current_camera_health_established", "false".to_owned()),
    ])
}
