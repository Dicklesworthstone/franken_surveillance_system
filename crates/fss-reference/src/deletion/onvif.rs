#![forbid(unsafe_code)]
//! Admit source-verified ONVIF metadata publications to the existing import lifecycle.
//! A ledger name only discovers a candidate; the ONVIF owner replays its exact frozen source
//! interpretation, manifest and current publication before sensor or closure membership exists.

use fss_core::{ContentDigest, SensorId};

use super::DeletionError;
use crate::onvif::metadata::{MetadataError, lifecycle_sensor};
use crate::{ReferenceDeployment, ReplayCx};

const BATCH_PREFIX: &str = "batch:local-root:onvif-metadata-";

#[derive(Debug)]
pub(super) struct OnvifImport {
    pub(super) sensor: SensorId,
    pub(super) object_id: String,
    slot_unit: String,
}

impl OnvifImport {
    pub(super) fn owns(&self, id: &str) -> bool {
        id == self.slot_unit
    }
}

/// Recognize only an exact immutable publication identity, never a similarly prefixed child.
pub(super) fn identity(batch: &str) -> Option<ContentDigest> {
    let hex = batch.strip_prefix(BATCH_PREFIX)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    ContentDigest::parse(format!("sha256:{hex}")).ok()
}

pub(super) fn has_terminal(deployment: &ReferenceDeployment, import: ContentDigest) -> bool {
    deployment
        .ledger()
        .batches()
        .iter()
        .any(|batch| identity(batch.batch_id.as_str()) == Some(import))
}

pub(super) fn slot_unit(import: ContentDigest) -> String {
    format!("slot:onvif-metadata-{}", &import.to_text()[7..])
}

pub(super) fn inspect(
    deployment: &ReferenceDeployment,
    import: ContentDigest,
    cx: &ReplayCx,
) -> Result<OnvifImport, DeletionError> {
    if !has_terminal(deployment, import) {
        return Err(DeletionError::UnknownImport(import));
    }
    let sensor = lifecycle_sensor(deployment, import, cx).map_err(|error| match error {
        MetadataError::Cancelled => DeletionError::Cancelled {
            stage: super::STAGE_DELETION_SCAN,
        },
        MetadataError::Limit => DeletionError::Bound {
            limit: "onvif_metadata_verification",
        },
        MetadataError::EvidenceDeleted { identity, plan } => DeletionError::EvidenceDeleted {
            import: identity,
            plan,
        },
        _ => DeletionError::RecordMismatch,
    })?;
    let hex = &import.to_text()[7..];
    let slot = format!("onvif-metadata-{hex}");
    Ok(OnvifImport {
        sensor,
        object_id: format!("object:local-root:{slot}"),
        // Reachability batches are excluded from deletion units by the existing owner.
        // The verified visible root holds the recipe, source and projection closure.
        slot_unit: slot_unit(import),
    })
}
