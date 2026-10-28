#![forbid(unsafe_code)]
//! Custody-only lifecycle projection and shared native deletion fences.
//! No retained endpoint or owner approval becomes fresh network authority here.

use fss_core::{CanonicalDecoder, ContentDigest, SensorId};

use super::{
    CREATED_DOMAIN, RENEW_INTENT_DOMAIN, RENEWED_DOMAIN, RetainedCreateIntent, RetainedRenewIntent,
    RetainedRenewal, RetainedSubscription, RetainedUnsubscribe, UNSUBSCRIBED_DOMAIN, read_record,
    slot,
};
use crate::adapter_replay::ReplayAdmission;
use crate::deletion::DeletionIndex;
use crate::onvif::metadata::{self, MetadataError};
use crate::{ReferenceDeployment, ReplayCx};

/// The deletion/hold owner receives only verified owner-bound scope membership.
/// Full source, parent, root, exact ledger and tombstone checks remain in this owner.
pub(crate) fn lifecycle_sensor<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    identity: ContentDigest,
    is_intent: bool,
    cx: &ReplayCx<G>,
) -> Result<SensorId, MetadataError> {
    if is_intent {
        return Ok(RetainedCreateIntent::open(deployment, identity, None, cx)?
            .binding()
            .source
            .sensor_id
            .clone());
    }
    let (encoded, _) = read_record(deployment, identity, false, None, cx)?;
    let mut decoder = CanonicalDecoder::new(&encoded);
    match decoder.text()? {
        CREATED_DOMAIN => Ok(RetainedSubscription::open(deployment, identity, None, cx)?
            .binding()
            .source
            .sensor_id
            .clone()),
        UNSUBSCRIBED_DOMAIN => Ok(RetainedUnsubscribe::open(deployment, identity, None, cx)?
            .subscription()
            .binding()
            .source
            .sensor_id
            .clone()),
        RENEW_INTENT_DOMAIN => Ok(RetainedRenewIntent::open(deployment, identity, None, cx)?
            .subscription()
            .binding()
            .source
            .sensor_id
            .clone()),
        RENEWED_DOMAIN => Ok(RetainedRenewal::open(deployment, identity, None, cx)?
            .intent()
            .subscription()
            .binding()
            .source
            .sensor_id
            .clone()),
        _ => Err(MetadataError::Custody),
    }
}

pub(super) fn check_available<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    identity: ContentDigest,
    is_intent: bool,
    objects: impl IntoIterator<Item = ContentDigest>,
    cx: &ReplayCx<G>,
) -> Result<(), MetadataError> {
    metadata::checkpoint(cx, "onvif_control:deletion_fence")?;
    let deletions = DeletionIndex::read(deployment).map_err(|_| MetadataError::Custody)?;
    let unit = format!("slot:{}", slot(identity, is_intent)?.as_str());
    metadata::check_deleted_for_unit(&deletions, identity, &unit, objects)
}
