#![forbid(unsafe_code)]
//! Bounded discovery of complete verified control receipts after output or process loss.
//!
//! Missing catalog entries never prove that a remote subscription does not exist.
//! The caller gets the whole admitted catalog or a refusal; corrupt, unledgered,
//! missing, or over-budget receipts are never silently omitted. Explicitly deleted
//! receipts are excluded only after the native tombstone proof is verified.

use std::collections::BTreeMap;

use fss_core::{CanonicalDecoder, ContentDigest};

use super::{
    CREATED_DOMAIN, PARSER_GENERATION, RENEW_INTENT_DOMAIN, RENEWED_DOMAIN, RetainedCreateIntent,
    RetainedRenewIntent, RetainedRenewal, RetainedSubscription, RetainedUnsubscribe,
    RetainedUnsubscribeIntent, RetainedUnsubscribeOutcome, UNSUBSCRIBE_INTENT_DOMAIN,
    UNSUBSCRIBE_OUTCOME_DOMAIN, UNSUBSCRIBED_DOMAIN, read_record,
};
use crate::adapter_replay::ReplayAdmission;
use crate::deletion::DeletionIndex;
use crate::onvif::metadata::{self, MAX_HISTORY_BATCHES, MetadataError};
use crate::{ReferenceDeployment, ReplayCx};

/// Maximum number of verified control records returned by one complete scan.
pub const MAX_CATALOG_RECORDS: usize = 1024;

/// Historical receipt kind, distinct from the device's unknown current state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlKind {
    /// A request was durably prepared; dispatch/result may remain unknown.
    CreateIntent,
    /// A complete scoped Create response was retained.
    Created,
    /// A complete correlated Unsubscribe success was retained.
    Unsubscribed,
    /// A Renew request was durably prepared; dispatch/result may remain unknown.
    RenewIntent,
    /// A complete Renew response was retained, including refused or malformed responses.
    /// This kind alone does not establish that a lease was granted.
    Renewed,
    /// Cleanup was durably prepared; dispatch/result may remain unknown.
    UnsubscribeIntent,
    /// Complete cleanup HTTP response, including rejected/malformed/untimed bodies.
    UnsubscribeOutcome,
}

/// Bounded hash-only discovery record. No endpoint, reference parameter or raw source is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlDescriptor {
    /// Historical receipt kind, never an assertion of current remote active state.
    pub kind: ControlKind,
    /// Exact receipt identity for cold inspection.
    pub identity: ContentDigest,
    /// Exact immutable publication root.
    pub root: ContentDigest,
    /// Original pre-dispatch intent identity.
    pub intent_identity: ContentDigest,
    /// The original Create receipt identity for subsequent subscription records.
    pub subscription_identity: Option<ContentDigest>,
    /// Exact pre-dispatch Renew intent, preserving independent attempt/outcome linkage.
    pub renewal_intent_identity: Option<ContentDigest>,
    /// Exact pre-dispatch cleanup intent for a cleanup attempt or raw outcome.
    pub unsubscribe_intent_identity: Option<ContentDigest>,
    /// Original ledger commit sequence, preserving multiple observations separately.
    pub authority_sequence: u64,
}

/// Discover every control receipt under current authority, ordered by original ledger sequence.
///
/// Both visible roots and ledger references are scanned. A previously published
/// root that vanished therefore causes refusal rather than a false empty catalog.
/// The finite record ceiling is applied before source verification; the existing
/// bounded history, source sizes and native context budgets apply throughout.
pub fn list_control<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    max_records: usize,
    cx: &ReplayCx<G>,
) -> Result<Vec<ControlDescriptor>, MetadataError> {
    if max_records == 0 || max_records > MAX_CATALOG_RECORDS {
        return Err(MetadataError::InvalidBinding);
    }
    metadata::admit(deployment, cx, "onvif_control:catalog")?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    metadata::history_work(deployment)?;
    metadata::checkpoint(cx, "onvif_control:catalog_deletions")?;
    let deletions = DeletionIndex::read(deployment).map_err(|_| MetadataError::Custody)?;
    let mut candidates = BTreeMap::<(ContentDigest, bool), ContentDigest>::new();
    for batch in deployment.ledger().batches() {
        metadata::checkpoint(cx, "onvif_control:catalog_history")?;
        for delta in &batch.deltas {
            if let Some(name) = delta.object_id.as_str().strip_prefix("object:local-root:") {
                insert_candidate(
                    &mut candidates,
                    name,
                    delta.payload_digest,
                    max_records,
                    &deletions,
                )?;
            }
        }
    }
    for (index, root) in deployment.publisher().visible_roots().enumerate() {
        if index >= MAX_HISTORY_BATCHES {
            return Err(MetadataError::Limit);
        }
        metadata::checkpoint(cx, "onvif_control:catalog_root")?;
        insert_candidate(
            &mut candidates,
            root.slot.as_str(),
            root.root,
            max_records,
            &deletions,
        )?;
    }
    let mut descriptors = Vec::with_capacity(candidates.len());
    for ((identity, is_intent), root) in candidates {
        metadata::checkpoint(cx, "onvif_control:catalog_verify")?;
        match describe(deployment, identity, is_intent, root, cx) {
            Ok(descriptor) => descriptors.push(descriptor),
            // A parent/source can be a deleted derivative even when this identity was not
            // itself a selected scope member. Its owner has verified the exact tombstone.
            Err(MetadataError::EvidenceDeleted { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    descriptors.sort_unstable_by_key(|item| (item.authority_sequence, item.identity));
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    metadata::checkpoint(cx, "onvif_control:catalog_complete")?;
    Ok(descriptors)
}

/// Read small immutable record headers to select one subscription's cleanup records before
/// loading complete sources. This is a targeted custody query, not a claim about other sessions.
/// A damaged candidate or parent cannot silently disappear from the selected history.
pub(super) fn list_cleanup_control<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    subscription: ContentDigest,
    cx: &ReplayCx<G>,
) -> Result<Vec<ControlDescriptor>, MetadataError> {
    metadata::admit(deployment, cx, "onvif_control:cleanup_catalog")?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    metadata::history_work(deployment)?;
    let deletions = DeletionIndex::read(deployment).map_err(|_| MetadataError::Custody)?;
    let mut candidates = BTreeMap::new();
    for batch in deployment.ledger().batches() {
        metadata::checkpoint(cx, "onvif_control:cleanup_catalog_history")?;
        for delta in &batch.deltas {
            if let Some(name) = delta.object_id.as_str().strip_prefix("object:local-root:") {
                insert_candidate(
                    &mut candidates,
                    name,
                    delta.payload_digest,
                    MAX_CATALOG_RECORDS,
                    &deletions,
                )?;
            }
        }
    }
    for (index, root) in deployment.publisher().visible_roots().enumerate() {
        if index >= MAX_HISTORY_BATCHES {
            return Err(MetadataError::Limit);
        }
        metadata::checkpoint(cx, "onvif_control:cleanup_catalog_root")?;
        insert_candidate(
            &mut candidates,
            root.slot.as_str(),
            root.root,
            MAX_CATALOG_RECORDS,
            &deletions,
        )?;
    }
    let mut descriptors = Vec::new();
    for ((identity, is_intent), root) in candidates {
        if is_intent {
            continue;
        }
        metadata::checkpoint(cx, "onvif_control:cleanup_catalog_record")?;
        let (encoded, _) = match read_record(deployment, identity, false, Some(root), cx) {
            Ok(value) => value,
            Err(MetadataError::EvidenceDeleted { .. }) => continue,
            Err(error) => return Err(error),
        };
        let mut d = CanonicalDecoder::new(&encoded);
        let domain = d.text()?;
        let parent = match domain {
            CREATED_DOMAIN | RENEW_INTENT_DOMAIN | RENEWED_DOMAIN => continue,
            UNSUBSCRIBED_DOMAIN | UNSUBSCRIBE_INTENT_DOMAIN => {
                if d.text()? != PARSER_GENERATION {
                    return Err(MetadataError::Custody);
                }
                d.digest()?
            }
            UNSUBSCRIBE_OUTCOME_DOMAIN => {
                if d.text()? != PARSER_GENERATION {
                    return Err(MetadataError::Custody);
                }
                let intent = d.digest()?;
                let (parent, _) = match read_record(deployment, intent, false, None, cx) {
                    Ok(value) => value,
                    Err(MetadataError::EvidenceDeleted { .. }) => continue,
                    Err(error) => return Err(error),
                };
                let mut p = CanonicalDecoder::new(&parent);
                if p.text()? != UNSUBSCRIBE_INTENT_DOMAIN || p.text()? != PARSER_GENERATION {
                    return Err(MetadataError::Custody);
                }
                p.digest()?
            }
            _ => return Err(MetadataError::Custody),
        };
        if parent != subscription {
            continue;
        }
        match describe(deployment, identity, false, root, cx) {
            Ok(descriptor) => descriptors.push(descriptor),
            Err(MetadataError::EvidenceDeleted { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    descriptors.sort_unstable_by_key(|item| (item.authority_sequence, item.identity));
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    metadata::checkpoint(cx, "onvif_control:cleanup_catalog_complete")?;
    Ok(descriptors)
}

fn describe<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    identity: ContentDigest,
    is_intent: bool,
    root: ContentDigest,
    cx: &ReplayCx<G>,
) -> Result<ControlDescriptor, MetadataError> {
    Ok(if is_intent {
        let intent = RetainedCreateIntent::open(deployment, identity, Some(root), cx)?;
        ControlDescriptor {
            kind: ControlKind::CreateIntent,
            identity,
            root,
            intent_identity: identity,
            subscription_identity: None,
            renewal_intent_identity: None,
            unsubscribe_intent_identity: None,
            authority_sequence: intent.authority_anchor().commit_sequence,
        }
    } else {
        let (encoded, _) = read_record(deployment, identity, false, Some(root), cx)?;
        let mut decoder = CanonicalDecoder::new(&encoded);
        match decoder.text()? {
            CREATED_DOMAIN => {
                let created = RetainedSubscription::open(deployment, identity, Some(root), cx)?;
                ControlDescriptor {
                    kind: ControlKind::Created,
                    identity,
                    root,
                    intent_identity: created.intent_identity(),
                    subscription_identity: Some(identity),
                    renewal_intent_identity: None,
                    unsubscribe_intent_identity: None,
                    authority_sequence: created.authority_anchor().commit_sequence,
                }
            }
            UNSUBSCRIBED_DOMAIN => {
                let ended = RetainedUnsubscribe::open(deployment, identity, Some(root), cx)?;
                ControlDescriptor {
                    kind: ControlKind::Unsubscribed,
                    identity,
                    root,
                    intent_identity: ended.subscription().intent_identity(),
                    subscription_identity: Some(ended.subscription_identity()),
                    renewal_intent_identity: None,
                    unsubscribe_intent_identity: None,
                    authority_sequence: ended.authority_anchor().commit_sequence,
                }
            }
            RENEW_INTENT_DOMAIN => {
                let intent = RetainedRenewIntent::open(deployment, identity, Some(root), cx)?;
                ControlDescriptor {
                    kind: ControlKind::RenewIntent,
                    identity,
                    root,
                    intent_identity: intent.subscription().intent_identity(),
                    subscription_identity: Some(intent.subscription().identity()),
                    renewal_intent_identity: Some(identity),
                    unsubscribe_intent_identity: None,
                    authority_sequence: intent.authority_anchor().commit_sequence,
                }
            }
            RENEWED_DOMAIN => {
                let renewed = RetainedRenewal::open(deployment, identity, Some(root), cx)?;
                ControlDescriptor {
                    kind: ControlKind::Renewed,
                    identity,
                    root,
                    intent_identity: renewed.intent().subscription().intent_identity(),
                    subscription_identity: Some(renewed.intent().subscription().identity()),
                    renewal_intent_identity: Some(renewed.intent().identity()),
                    unsubscribe_intent_identity: None,
                    authority_sequence: renewed.authority_anchor().commit_sequence,
                }
            }
            UNSUBSCRIBE_INTENT_DOMAIN => {
                let intent = RetainedUnsubscribeIntent::open(deployment, identity, Some(root), cx)?;
                ControlDescriptor {
                    kind: ControlKind::UnsubscribeIntent,
                    identity,
                    root,
                    intent_identity: intent.subscription().intent_identity(),
                    subscription_identity: Some(intent.subscription().identity()),
                    renewal_intent_identity: None,
                    unsubscribe_intent_identity: Some(identity),
                    authority_sequence: intent.authority_anchor().commit_sequence,
                }
            }
            UNSUBSCRIBE_OUTCOME_DOMAIN => {
                let outcome =
                    RetainedUnsubscribeOutcome::open(deployment, identity, Some(root), cx)?;
                ControlDescriptor {
                    kind: ControlKind::UnsubscribeOutcome,
                    identity,
                    root,
                    intent_identity: outcome.intent().subscription().intent_identity(),
                    subscription_identity: Some(outcome.intent().subscription().identity()),
                    renewal_intent_identity: None,
                    unsubscribe_intent_identity: Some(outcome.intent().identity()),
                    authority_sequence: outcome.authority_anchor().commit_sequence,
                }
            }
            _ => return Err(MetadataError::Custody),
        }
    })
}

fn insert_candidate(
    candidates: &mut BTreeMap<(ContentDigest, bool), ContentDigest>,
    slot: &str,
    root: ContentDigest,
    maximum: usize,
    deletions: &DeletionIndex,
) -> Result<(), MetadataError> {
    let (hex, is_intent) = if let Some(hex) = slot.strip_prefix("onvif-create-intent-") {
        (hex, true)
    } else if let Some(hex) = slot.strip_prefix("onvif-subscription-") {
        (hex, false)
    } else {
        return Ok(());
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MetadataError::Custody);
    }
    let identity = ContentDigest::parse(&format!("sha256:{hex}"))?;
    match metadata::check_deleted_for_unit(
        deletions,
        identity,
        &format!("slot:{slot}"),
        [identity, root],
    ) {
        Ok(()) => {}
        Err(MetadataError::EvidenceDeleted { .. }) => return Ok(()),
        Err(error) => return Err(error),
    }
    let key = (identity, is_intent);
    if let Some(existing) = candidates.get(&key) {
        if *existing != root {
            return Err(MetadataError::Custody);
        }
    } else {
        if candidates.len() >= maximum {
            return Err(MetadataError::Limit);
        }
        candidates.insert(key, root);
    }
    Ok(())
}
