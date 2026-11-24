#![forbid(unsafe_code)]
//! Constants, registered ledger delta families, cancellation stages, and lineage validation
//! for [`super::ReferenceDeployment`].

use fss_publication::{PublishCutPoint, ROOT_REACHABILITY_FAMILY, ROOT_RETRACTION_FAMILY};

use crate::error::ReferenceError;

/// Canonical schema ID for reference deployment layout.
pub const DEPLOYMENT_LAYOUT_SCHEMA: &str = "fss.reference_deployment.layout.v1";
/// Format version for reference deployment layout.
pub const DEPLOYMENT_LAYOUT_FORMAT_VERSION: u32 = 1;
/// Fixed filename for layout descriptor under deployment root.
pub const DEPLOYMENT_LAYOUT_FILENAME: &str = "LAYOUT";

/// Relative path to authority ledger journal.
pub const RELATIVE_PATH_LEDGER: &str = "ledger/journal.fssj";
/// Relative path to object storage directory.
pub const RELATIVE_PATH_OBJECTS: &str = "objects";
/// Relative path to durable effect journal.
pub const RELATIVE_PATH_EFFECTS: &str = "effects/journal.fssj";

/// Registered ledger delta family: sensor capsule.
pub const FAMILY_SENSOR_CAPSULE: &str = "sensor_capsule";
/// Registered ledger delta family: event revision.
pub const FAMILY_EVENT_REVISION: &str = "event_revision";
/// Registered ledger delta family: alert effect outcome.
pub const FAMILY_ALERT_EFFECT_OUTCOME: &str = "alert_effect_outcome";
/// Reserved ledger delta family: accumulated sensor-tamper witness of an event revision.
pub const FAMILY_SENSOR_TAMPER_STATUS: &str = "sensor_tamper_status";
/// Registered ledger delta family: file import lifecycle object (generation 1 = in progress,
/// generation 2 = complete).
pub const FAMILY_FILE_IMPORT: &str = "file_import";
/// Registered ledger delta family: file import manifest.
pub const FAMILY_FILE_IMPORT_MANIFEST: &str = "file_import_manifest";
/// Registered ledger delta family: acquisition transition.
pub const FAMILY_ACQUISITION_TRANSITION: &str = "acquisition_transition";
/// Registered ledger delta family: decode receipt.
pub const FAMILY_DECODE_RECEIPT: &str = "decode_receipt";
/// Registered ledger delta family: model invocation receipt.
pub const FAMILY_MODEL_INVOCATION_RECEIPT: &str = "model_invocation_receipt";
/// Registered ledger delta family: executor model result.
pub const FAMILY_EXECUTOR_MODEL_RESULT: &str = "executor_model_result";
/// Registered ledger delta family: twin localization receipt.
pub const FAMILY_TWIN_LOCALIZATION_RECEIPT: &str = "twin_localization_receipt";
/// Reserved authority: an owner's withdrawal of one exact adopted calibration.
/// Only [`crate::ingest::calibration_invalidation::invalidate`] may publish this family.
pub const FAMILY_CALIBRATION_INVALIDATION: &str = "calibration_invalidation";
/// Registered ledger delta family: retained coverage witnesses of one analysed recording
/// (`ingest::recorded_coverage`), committed only after exact operator approval.
pub const FAMILY_COVERAGE_WITNESS: &str = "coverage_witness";
/// Registered ledger delta family: an owner-declared per-sensor privacy mask policy
/// (`ingest::privacy_mask`), one generation per exact approval; plane authority.
pub const FAMILY_PRIVACY_MASK_POLICY: &str = "privacy_mask_policy";
/// Reserved retention authority: an indefinite import-closure hold and its explicit release.
/// Only [`crate::deletion::holds::commit_hold`] may publish this family or its object namespace.
pub const FAMILY_EVIDENCE_HOLD: &str = "evidence_hold";
/// Reserved per-sensor retention settings; only the exact approved policy owner may mutate them.
pub const FAMILY_RETENTION_POLICY: &str = "retention_policy";
/// Registered ledger delta family: the sealed deletion plan of one retained import
/// ([`crate::deletion`]), appended before any byte is removed; plane authority. Reserved.
pub const FAMILY_DELETION_RECORD: &str = "deletion_record";
/// Registered ledger delta family: the successor generation of a ledger object whose content a
/// durable deletion record removed; the object's history is kept, never rewritten. Reserved.
pub const FAMILY_DELETION_TOMBSTONE: &str = "deletion_tombstone";
/// Registered ledger delta family: the deletion-completion record naming exactly what was
/// removed, retained and not provable; appended last. Reserved.
pub const FAMILY_DELETION_COMPLETION: &str = "deletion_completion";

/// Known ledger delta families table.
pub const KNOWN_LEDGER_DELTA_FAMILIES: &[&str] = &[
    FAMILY_SENSOR_CAPSULE,
    FAMILY_EVENT_REVISION,
    FAMILY_ALERT_EFFECT_OUTCOME,
    FAMILY_FILE_IMPORT,
    FAMILY_FILE_IMPORT_MANIFEST,
    FAMILY_ACQUISITION_TRANSITION,
    FAMILY_DECODE_RECEIPT,
    FAMILY_MODEL_INVOCATION_RECEIPT,
    FAMILY_EXECUTOR_MODEL_RESULT,
    FAMILY_TWIN_LOCALIZATION_RECEIPT,
    FAMILY_CALIBRATION_INVALIDATION,
    FAMILY_COVERAGE_WITNESS,
    FAMILY_PRIVACY_MASK_POLICY,
    FAMILY_EVIDENCE_HOLD,
    FAMILY_RETENTION_POLICY,
    FAMILY_DELETION_RECORD,
    FAMILY_DELETION_TOMBSTONE,
    FAMILY_DELETION_COMPLETION,
    crate::deployment_backup::FAMILY_RESTORE_FENCE,
    crate::ingest::historical_health::FAMILY_HISTORICAL_HEALTH,
    crate::discovery::retained_liveness::FAMILY_SENSOR_LIVENESS,
];

/// Replay cancellation stage: open deployment.
pub const STAGE_DEPLOYMENT_OPEN: &str = "deployment_open";
/// Replay cancellation stage: stage objects.
pub const STAGE_STAGE_OBJECTS: &str = "stage_objects";
/// Replay cancellation stage: stage manifest.
pub const STAGE_STAGE_MANIFEST: &str = "stage_manifest";
/// Replay cancellation stage: publish root.
pub const STAGE_PUBLISH_ROOT: &str = "publish_root";
/// Replay cancellation stage: publish event.
pub const STAGE_PUBLISH_EVENT: &str = "publish_event";
/// Replay cancellation stage: append batch.
pub const STAGE_APPEND_BATCH: &str = "append_batch";
/// Replay cancellation stage: evaluate policy.
pub const STAGE_EVALUATE_POLICY: &str = "evaluate_policy";
/// Replay cancellation stage: dispatch alert.
pub const STAGE_DISPATCH_ALERT: &str = "dispatch_alert";
/// Replay cancellation stage: compile situation.
pub const STAGE_COMPILE_SITUATION: &str = "compile_situation";
/// Replay cancellation stage: seal handoff.
pub const STAGE_SEAL_HANDOFF: &str = "seal_handoff";
/// Replay cancellation stage: publication cut point after children verified.
pub const STAGE_AFTER_CHILDREN_VERIFIED: &str = "after_children_verified";
/// Replay cancellation stage: publication cut point after manifest body.
pub const STAGE_AFTER_MANIFEST_BODY: &str = "after_manifest_body";
/// Replay cancellation stage: publication cut point after root temp write.
pub const STAGE_AFTER_ROOT_TEMP_WRITE: &str = "after_root_temp_write";
/// Replay cancellation stage: publication cut point after root rename.
pub const STAGE_AFTER_ROOT_RENAME: &str = "after_root_rename";

/// Exported list of all deployment cancellation checkpoint stages.
pub const DEPLOYMENT_CANCEL_STAGES: &[&str] = &[
    STAGE_DEPLOYMENT_OPEN,
    STAGE_STAGE_OBJECTS,
    STAGE_STAGE_MANIFEST,
    STAGE_PUBLISH_ROOT,
    STAGE_PUBLISH_EVENT,
    STAGE_APPEND_BATCH,
    STAGE_EVALUATE_POLICY,
    STAGE_DISPATCH_ALERT,
    STAGE_COMPILE_SITUATION,
    STAGE_SEAL_HANDOFF,
    STAGE_AFTER_CHILDREN_VERIFIED,
    STAGE_AFTER_MANIFEST_BODY,
    STAGE_AFTER_ROOT_TEMP_WRITE,
    STAGE_AFTER_ROOT_RENAME,
];

/// The public entry point that owns a reserved ledger delta family, or `None` if the family may
/// be appended through [`super::ReferenceDeployment::append_batch`].
///
/// An event revision and its sensor-tamper witness are only ever committed together by
/// `publish_event`, after the lineage tamper step; a root reachability claim only by
/// `publish_and_commit`, after the root is durable. Appending them directly would put
/// unguarded authority into the ledger.
pub(super) fn reserved_family_entry_point(family: &str) -> Option<&'static str> {
    match family {
        FAMILY_CALIBRATION_INVALIDATION => Some("ingest::calibration_invalidation::invalidate"),
        FAMILY_EVENT_REVISION | FAMILY_SENSOR_TAMPER_STATUS => Some("publish_event"),
        crate::evidence_export::FAMILY_EVIDENCE_EXPORT => Some("evidence_export::commit_export"),
        crate::review_media::FAMILY_REVIEW_MEDIA
        | crate::review_media::FAMILY_REVIEW_REVOCATION => {
            Some("review_media::commit_review_media/revoke_review_media")
        }
        crate::review_media::delivery::FAMILY_REVIEW_DELIVERY_STARTED
        | crate::review_media::delivery::FAMILY_REVIEW_DELIVERY_VERIFIED => {
            Some("review_media::delivery::begin_review_delivery/verify_review_delivery")
        }
        crate::deployment_backup::FAMILY_RESTORE_FENCE => Some("deployment_backup::restore_backup"),
        crate::ingest::historical_health::FAMILY_HISTORICAL_HEALTH => {
            Some("ingest::historical_health::HistoricalHealthDiagnostic::retain")
        }
        crate::discovery::retained_liveness::FAMILY_SENSOR_LIVENESS => {
            Some("discovery::retained_liveness::retain_discovery_window")
        }
        ROOT_REACHABILITY_FAMILY => Some("publish_and_commit"),
        FAMILY_EVIDENCE_HOLD => Some("deletion::holds::commit_hold"),
        FAMILY_RETENTION_POLICY => Some("deletion::retention::policy::commit_policy_change"),
        FAMILY_DELETION_RECORD
        | FAMILY_DELETION_TOMBSTONE
        | FAMILY_DELETION_COMPLETION
        | ROOT_RETRACTION_FAMILY => Some("deletion::commit_deletion"),
        _ => None,
    }
}

/// Validates that `site_lineage` meets token grammar constraints.
///
/// Refuses empty strings, whitespace, control characters, and non-ASCII characters.
pub fn validate_site_lineage(lineage: &str) -> Result<(), ReferenceError> {
    if lineage.is_empty() {
        return Err(ReferenceError::InvalidSpec(
            "deployment site_lineage is empty",
        ));
    }
    if lineage.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return Err(ReferenceError::InvalidSpec(
            "deployment site_lineage contains whitespace or control characters",
        ));
    }
    if !lineage.chars().all(|c| c.is_ascii_graphic()) {
        return Err(ReferenceError::InvalidSpec(
            "deployment site_lineage must consist of ASCII graphic characters",
        ));
    }
    Ok(())
}

/// Registered deployment stage name of a publication cut point.
///
/// Every value is a member of [`DEPLOYMENT_CANCEL_STAGES`].
pub(crate) const fn publish_cut_point_stage(point: PublishCutPoint) -> &'static str {
    match point {
        PublishCutPoint::AfterChildrenVerified => STAGE_AFTER_CHILDREN_VERIFIED,
        PublishCutPoint::AfterManifestBody => STAGE_AFTER_MANIFEST_BODY,
        PublishCutPoint::AfterRootTempWrite => STAGE_AFTER_ROOT_TEMP_WRITE,
        PublishCutPoint::AfterRootRename => STAGE_AFTER_ROOT_RENAME,
    }
}
