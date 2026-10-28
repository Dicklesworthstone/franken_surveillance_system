#![forbid(unsafe_code)]
//! Admit source-verified ONVIF metadata and control publications to the existing lifecycle.
//! A ledger name only discovers a candidate; each ONVIF owner verifies exact source,
//! parent custody, manifest and current publication before sensor or closure membership exists.

use fss_core::{ContentDigest, SensorId};

use super::DeletionError;
use crate::adapter_replay::ReplayAdmission;
use crate::onvif::metadata::MetadataError;
use crate::onvif::{control, metadata};
use crate::{ReferenceDeployment, ReplayCx};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OnvifKind {
    Metadata,
    CreateIntent,
    Subscription,
}
impl OnvifKind {
    fn prefix(self) -> &'static str {
        match self {
            Self::Metadata => "onvif-metadata-",
            Self::CreateIntent => "onvif-create-intent-",
            Self::Subscription => "onvif-subscription-",
        }
    }
}

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

/// Recognize an exact immutable publication identity, never a similarly prefixed child.
pub(super) fn identity(batch: &str) -> Option<(OnvifKind, ContentDigest)> {
    let slot = batch.strip_prefix("batch:local-root:")?;
    let kind = [
        OnvifKind::Metadata,
        OnvifKind::CreateIntent,
        OnvifKind::Subscription,
    ]
    .into_iter()
    .find(|kind| slot.starts_with(kind.prefix()))?;
    let hex = slot.strip_prefix(kind.prefix())?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some((kind, ContentDigest::parse(format!("sha256:{hex}")).ok()?))
}

pub(super) fn has_terminal(deployment: &ReferenceDeployment, import: ContentDigest) -> bool {
    deployment
        .ledger()
        .batches()
        .iter()
        .any(|batch| identity(batch.batch_id.as_str()).is_some_and(|(_, digest)| digest == import))
}

pub(super) fn slot_unit(kind: OnvifKind, import: ContentDigest) -> String {
    format!("slot:{}{}", kind.prefix(), &import.to_text()[7..])
}

pub(super) fn inspect(
    deployment: &ReferenceDeployment,
    import: ContentDigest,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<OnvifImport, DeletionError> {
    let mut matches = deployment
        .ledger()
        .batches()
        .iter()
        .filter_map(|batch| identity(batch.batch_id.as_str()))
        .filter_map(|(kind, digest)| (digest == import).then_some(kind));
    let kind = matches.next().ok_or(DeletionError::UnknownImport(import))?;
    // One lifecycle identity must never ambiguously select multiple owners.
    if matches.next().is_some() {
        return Err(DeletionError::RecordMismatch);
    }
    let sensor = match kind {
        OnvifKind::Metadata => metadata::lifecycle_sensor(deployment, import, cx),
        OnvifKind::CreateIntent => control::lifecycle_sensor(deployment, import, true, cx),
        OnvifKind::Subscription => control::lifecycle_sensor(deployment, import, false, cx),
    }
    .map_err(|error| match error {
        MetadataError::Cancelled => DeletionError::Cancelled {
            stage: super::STAGE_DELETION_SCAN,
        },
        MetadataError::Limit => DeletionError::Bound {
            limit: "onvif_custody_verification",
        },
        MetadataError::EvidenceDeleted { identity, plan } => DeletionError::EvidenceDeleted {
            import: identity,
            plan,
        },
        _ => DeletionError::RecordMismatch,
    })?;
    let slot = format!("{}{}", kind.prefix(), &import.to_text()[7..]);
    Ok(OnvifImport {
        sensor,
        object_id: format!("object:local-root:{slot}"),
        // Existing reachability batches are authority; the verified root holds the source.
        slot_unit: slot_unit(kind, import),
    })
}
