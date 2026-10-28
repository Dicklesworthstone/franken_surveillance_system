#![forbid(unsafe_code)]
//! Immutable ONVIF subscription intent and Create-response custody.
//!
//! An intent is durable before dispatch. It proves what the owner admitted, never
//! that Create was sent or that retry is safe. A retained Create response preserves
//! its exact endpoint reference even when no poll reaches custody. These historical
//! records grant no current network authority or assertion of remote active state.

mod catalog;
mod codec;
mod lifecycle;
mod renewal;
mod termination;

pub use catalog::{ControlDescriptor, ControlKind, MAX_CATALOG_RECORDS, list_control};
pub(crate) use lifecycle::lifecycle_sensor;
pub use renewal::{
    RENEW_INTENT_DOMAIN, RENEWED_DOMAIN, RenewIntentBinding, RenewOutcomeBinding,
    RetainedRenewIntent, RetainedRenewal, STAGE_RENEW_INTENT_PUBLISH, STAGE_RENEWED_PUBLISH,
    prepare_renew, retain_renewal,
};
pub use termination::{
    RetainedUnsubscribe, STAGE_UNSUBSCRIBED_PUBLISH, UNSUBSCRIBED_DOMAIN, UnsubscribeBinding,
    retain_unsubscribed,
};

use std::fmt;

use fss_core::{
    CanonicalEncode, CaptureInterval, ContentDigest, DigestAlgorithm, LedgerAnchor, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::{LocalPublicationState, SlotName};

use super::http::HttpRoute;
use super::metadata::{
    self, MAX_HISTORY_BATCHES, MAX_HISTORY_DELTAS, MAX_SOURCE_BYTES, MetadataError, SourceBinding,
};
use super::pullpoint::{MAX_SESSION_NS, route_in_service_root};
use super::wire::{
    PullPointSubscription, create_pull_point_request, parse_pull_point_subscription,
    require_relates_to,
};
use crate::adapter_replay::ReplayAdmission;
use crate::{ReferenceDeployment, ReplayCx};

/// Frozen canonical intent format, distinct from event/analytics imports.
pub const INTENT_DOMAIN: &str = "fss.onvif_pullpoint_create_intent.v1";
/// Frozen canonical observed Create-response format.
pub const CREATED_DOMAIN: &str = "fss.onvif_pullpoint_created.v1";
/// Exact bounded SOAP interpretation used for cold response verification.
pub const PARSER_GENERATION: &str = "gen:fss1:onvif-pullpoint-control-v1";
/// Complete canonical record ceiling, including exact private route strings.
pub const MAX_CONTROL_RECORD_BYTES: usize = 8192;
/// Last cancellable admission before publishing the pre-dispatch intent.
pub const STAGE_CREATE_INTENT_PUBLISH: &str = "onvif_control:intent_publish";
/// Last cancellable admission before publishing a complete Create response.
pub const STAGE_CREATED_PUBLISH: &str = "onvif_control:created_publish";

/// Owner-approved immutable Create request, before any dispatch.
///
/// The source interval is a point at the local request admission time. It does
/// not claim a received response; the later receipt derives its receive interval
/// from this point and the observed monotonic completion.
#[derive(Clone, Eq, PartialEq)]
pub struct CreateIntentBinding {
    /// Independent sensor/device/profile attribution and local admission point.
    pub source: SourceBinding,
    /// Exact literal peer, HTTP authority/target, generation and explicit approval.
    pub events: HttpRoute,
    /// Approved subtree for any camera-returned subscription address.
    pub service_root: String,
    /// Fresh owner-generated identity for this logical Create request.
    pub message_id: String,
    /// Original monotonic admission time, before intent storage or HTTP retries.
    pub started_ns: u64,
    /// Explicit finite lifetime requested from the camera, without remote guarantees.
    pub lifetime_seconds: u32,
}

impl CreateIntentBinding {
    /// Validate the complete bounded request without performing I/O.
    pub fn validate(&self) -> Result<(), MetadataError> {
        self.source.validate()?;
        if self.source.receive_interval.earliest != self.source.receive_interval.latest
            || !self.events.is_event_subscription()
            || self.events.plaintext_approval().algorithm() != DigestAlgorithm::Sha256
            || !route_in_service_root(&self.events, &self.service_root)
        {
            return Err(MetadataError::InvalidBinding);
        }
        create_pull_point_request(
            &format!("http://{}{}", self.events.authority(), self.events.target()),
            self.lifetime_seconds,
        )
        .and_then(|request| request.with_message_id(&self.message_id))
        .map_err(|_| MetadataError::InvalidBinding)?;
        Ok(())
    }

    fn receive_interval(&self, completed_ns: u64) -> Result<CaptureInterval, MetadataError> {
        let elapsed = completed_ns
            .checked_sub(self.started_ns)
            .filter(|elapsed| *elapsed <= MAX_SESSION_NS)
            .ok_or(MetadataError::InvalidBinding)?;
        let end = self
            .source
            .receive_interval
            .earliest
            .0
            .checked_add(i128::from(elapsed))
            .ok_or(MetadataError::InvalidBinding)?;
        Ok(CaptureInterval::new(
            self.source.receive_interval.earliest,
            TimestampNs(end),
        )?)
    }
}

impl fmt::Debug for CreateIntentBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateIntentBinding")
            .field("source", &self.source)
            .field("event_route_digest", &self.events.digest())
            .field("started_ns", &self.started_ns)
            .field("lifetime_seconds", &self.lifetime_seconds)
            .finish_non_exhaustive()
    }
}

/// Durable pre-dispatch receipt. Its existence alone means dispatch/result unknown.
#[derive(Clone)]
pub struct RetainedCreateIntent {
    identity: ContentDigest,
    root: ContentDigest,
    record: codec::IntentRecord,
    anchor: LedgerAnchor,
    newly_prepared: bool,
}

impl RetainedCreateIntent {
    /// Cold verification never repairs previously published source or substitutes a root.
    pub fn open<G: ReplayAdmission>(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx<G>,
    ) -> Result<Self, MetadataError> {
        let (encoded, visible_root) = read_record(deployment, identity, true, expected_root, cx)?;
        let record = codec::decode_intent(&encoded)?;
        if record.site != deployment.site_lineage() {
            return Err(MetadataError::Custody);
        }
        let manifest = intent_manifest(identity)?;
        verify_manifest(deployment, identity, true, &manifest, visible_root, cx)?;
        let anchor = metadata::check_publication(
            deployment,
            &slot(identity, true)?,
            &manifest,
            &record.binding.source,
            cx,
        )?;
        finish_read(deployment, &slot(identity, true)?, cx)?;
        Ok(Self {
            identity,
            root: visible_root,
            record,
            anchor,
            newly_prepared: false,
        })
    }

    /// Stable intent identity; keep it even if dispatch or response retention fails.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// True only for this invocation's first publication of a new intent.
    /// Cold opens and exact storage retries are false and must never authorize redispatch.
    pub const fn newly_prepared(&self) -> bool {
        self.newly_prepared
    }
    /// Exact durable immutable intent root.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Frozen owner request. This historical approval cannot authorize a new session.
    pub fn binding(&self) -> &CreateIntentBinding {
        &self.record.binding
    }
    /// Original authority-ledger custody anchor, stable across exact retries.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}
impl fmt::Debug for RetainedCreateIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedCreateIntent")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("event_route_digest", &self.record.binding.events.digest())
            .finish_non_exhaustive()
    }
}

/// Historical observed Create response with its exact intent and source custody.
///
/// This is not proof that the subscription is active now, that cleanup has not
/// already occurred, or that current credentials/permissions remain valid.
#[derive(Clone)]
pub struct RetainedSubscription {
    identity: ContentDigest,
    root: ContentDigest,
    record: codec::CreatedRecord,
    intent: RetainedCreateIntent,
    source: Vec<u8>,
    subscription: PullPointSubscription,
    receive_interval: CaptureInterval,
    anchor: LedgerAnchor,
}

impl RetainedSubscription {
    /// Reopen solely from immutable source, intent and exact ledger custody.
    pub fn open<G: ReplayAdmission>(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx<G>,
    ) -> Result<Self, MetadataError> {
        let (encoded, visible_root) = read_record(deployment, identity, false, expected_root, cx)?;
        let record = codec::decode_created(&encoded)?;
        let intent = RetainedCreateIntent::open(deployment, record.intent, None, cx)?;
        let manifest = created_manifest(identity, &record, &intent)?;
        verify_manifest(deployment, identity, false, &manifest, visible_root, cx)?;
        let source = metadata::read(deployment, record.source, record.source_bytes, cx)?;
        if source.len() != record.source_bytes {
            return Err(MetadataError::Custody);
        }
        let (subscription, receive_interval) =
            validate_created(intent.binding(), &record, &source)?;
        let mut source_binding = intent.binding().source.clone();
        source_binding.receive_interval = receive_interval;
        let anchor = metadata::check_publication(
            deployment,
            &slot(identity, false)?,
            &manifest,
            &source_binding,
            cx,
        )?;
        finish_read(deployment, &slot(identity, false)?, cx)?;
        Ok(Self {
            identity,
            root: visible_root,
            record,
            intent,
            source,
            subscription,
            receive_interval,
            anchor,
        })
    }

    /// Exact immutable response receipt identity.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact durable root preserving intent, request and complete Create SOAP.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Original durable pre-dispatch intent identity.
    pub const fn intent_identity(&self) -> ContentDigest {
        self.record.intent
    }
    /// Verified parent receipt, including its own original custody anchor.
    pub fn intent(&self) -> &RetainedCreateIntent {
        &self.intent
    }
    /// Frozen request context, not a current network grant.
    pub fn binding(&self) -> &CreateIntentBinding {
        self.intent.binding()
    }
    /// Complete exact Create SOAP. Private endpoint and parameter values may occur here.
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    /// Exact Create SOAP digest.
    pub const fn source_digest(&self) -> ContentDigest {
        self.record.source
    }
    /// Exact Create SOAP byte length.
    pub const fn source_bytes(&self) -> usize {
        self.record.source_bytes
    }
    /// Bounded parsed endpoint reference, usable only under independently current authority.
    pub fn subscription(&self) -> &PullPointSubscription {
        &self.subscription
    }
    /// Original monotonic completion, never a trusted vendor clock.
    pub const fn completed_ns(&self) -> u64 {
        self.record.completed_ns
    }
    /// Whether a client Digest proof was sent, not server authentication.
    pub const fn client_authenticated(&self) -> bool {
        self.record.client_authenticated
    }
    /// Local receive interval derived from the retained admission origin and elapsed time.
    pub const fn receive_interval(&self) -> CaptureInterval {
        self.receive_interval
    }
    /// Original response-custody anchor, stable across exact retries.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}
impl fmt::Debug for RetainedSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedSubscription")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("intent", &self.record.intent)
            .field("source_digest", &self.record.source)
            .field("source_bytes", &self.record.source_bytes)
            .finish_non_exhaustive()
    }
}

/// Durably retain the complete immutable request before the caller dispatches Create.
///
/// A failed/indeterminate publication must be reconciled before dispatch. Retrying
/// this storage operation with exact bytes does not retry the remote operation.
pub fn prepare_create<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    binding: CreateIntentBinding,
    cx: &ReplayCx<G>,
) -> Result<RetainedCreateIntent, MetadataError> {
    admit_write(deployment, cx)?;
    let record = codec::IntentRecord {
        site: deployment.site_lineage().to_owned(),
        binding,
    };
    let encoded = codec::encode_intent(&record)?;
    let identity = ContentDigest::sha256(&encoded);
    let manifest = intent_manifest(identity)?;
    let newly_prepared = deployment
        .publisher()
        .root(&slot(identity, true)?)
        .is_none();
    let (root, anchor) = publish(
        deployment,
        identity,
        &manifest,
        &record.binding.source,
        &[encoded.as_slice()],
        true,
        STAGE_CREATE_INTENT_PUBLISH,
        cx,
    )?;
    let retained = RetainedCreateIntent {
        identity,
        root,
        record,
        anchor,
        newly_prepared,
    };
    cx.checkpoint_post_commit("onvif_control:intent_committed");
    Ok(retained)
}

/// Retain the complete Create response before the caller begins polling.
///
/// The response must correlate to the exact durable intent and yield a bounded
/// same-origin/subtree endpoint. Malformed/hostile responses leave only the intent,
/// whose dispatch/result remains unresolved. No endpoint is followed by this API.
pub fn retain_created<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    intent: &RetainedCreateIntent,
    completed_ns: u64,
    client_authenticated: bool,
    source: &[u8],
    cx: &ReplayCx<G>,
) -> Result<RetainedSubscription, MetadataError> {
    admit_write(deployment, cx)?;
    let intent = RetainedCreateIntent::open(
        deployment,
        intent.identity(),
        Some(intent.publication_root()),
        cx,
    )?;
    let record = codec::CreatedRecord {
        intent: intent.identity(),
        completed_ns,
        client_authenticated,
        source: ContentDigest::sha256(source),
        source_bytes: source.len(),
    };
    let (subscription, receive_interval) = validate_created(intent.binding(), &record, source)?;
    let encoded = codec::encode_created(&record)?;
    let identity = ContentDigest::sha256(&encoded);
    let manifest = created_manifest(identity, &record, &intent)?;
    let intent_encoded = codec::encode_intent(&intent.record)?;
    let intent_manifest_bytes = intent_manifest(intent.identity())?.canonical_bytes();
    let mut source_binding = intent.binding().source.clone();
    source_binding.receive_interval = receive_interval;
    let retained_source = source.to_vec();
    let (root, anchor) = publish(
        deployment,
        identity,
        &manifest,
        &source_binding,
        &[
            encoded.as_slice(),
            source,
            intent_encoded.as_slice(),
            intent_manifest_bytes.as_slice(),
        ],
        false,
        STAGE_CREATED_PUBLISH,
        cx,
    )?;
    let retained = RetainedSubscription {
        identity,
        root,
        record,
        intent,
        source: retained_source,
        subscription,
        receive_interval,
        anchor,
    };
    cx.checkpoint_post_commit("onvif_control:created_committed");
    Ok(retained)
}

fn validate_created(
    binding: &CreateIntentBinding,
    record: &codec::CreatedRecord,
    source: &[u8],
) -> Result<(PullPointSubscription, CaptureInterval), MetadataError> {
    binding.validate()?;
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    if source.len() != record.source_bytes || ContentDigest::sha256(source) != record.source {
        return Err(MetadataError::Custody);
    }
    let interval = binding.receive_interval(record.completed_ns)?;
    require_relates_to(source, &binding.message_id)?;
    let subscription = parse_pull_point_subscription(source)?;
    binding
        .events
        .event_subscription(subscription.endpoint(), &binding.service_root)
        .map_err(|_| MetadataError::InvalidBinding)?;
    Ok((subscription, interval))
}

fn admit_write<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    cx: &ReplayCx<G>,
) -> Result<(), MetadataError> {
    metadata::admit(deployment, cx, "onvif_control:admit")?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    let deltas = metadata::history_work(deployment)?;
    if deployment.ledger().batches().len() >= MAX_HISTORY_BATCHES || deltas >= MAX_HISTORY_DELTAS {
        return Err(MetadataError::Limit);
    }
    Ok(())
}

fn publish<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    identity: ContentDigest,
    manifest: &ObjectManifest,
    binding: &SourceBinding,
    objects: &[&[u8]],
    is_intent: bool,
    stage: &'static str,
    cx: &ReplayCx<G>,
) -> Result<(ContentDigest, LedgerAnchor), MetadataError> {
    let slot = slot(identity, is_intent)?;
    let manifest_bytes = manifest.canonical_bytes();
    lifecycle::check_available(
        deployment,
        identity,
        is_intent,
        std::iter::once(manifest.root()).chain(manifest.children().iter().copied()),
        cx,
    )?;
    if deployment.publisher().is_broken_slot(&slot) {
        return Err(MetadataError::Custody);
    }
    if let Some(existing) = deployment.publisher().root(&slot) {
        if existing.root != manifest.root() {
            return Err(MetadataError::Custody);
        }
        if existing.state == LocalPublicationState::Durable {
            deployment
                .publisher()
                .require_durable_record(&slot)
                .map_err(|_| MetadataError::Custody)?;
        }
        for bytes in objects.iter().copied().chain([manifest_bytes.as_slice()]) {
            let digest = ContentDigest::sha256(bytes);
            if metadata::read(deployment, digest, bytes.len(), cx)? != bytes {
                return Err(MetadataError::Custody);
            }
        }
        match metadata::check_publication(deployment, &slot, manifest, binding, cx) {
            Ok(_) | Err(MetadataError::Unavailable) => {}
            Err(error) => return Err(error),
        }
    } else {
        let object = format!("object:local-root:{}", slot.as_str());
        if deployment.ledger().batches().iter().any(|batch| {
            batch
                .deltas
                .iter()
                .any(|delta| delta.object_id.as_str() == object)
        }) {
            return Err(MetadataError::Custody);
        }
        metadata::checkpoint(cx, "onvif_control:stage")?;
        let staged = deployment.stage_and_publish(&slot, objects, cx)?;
        if staged.manifest != *manifest {
            return Err(MetadataError::Custody);
        }
    }
    metadata::checkpoint(cx, stage)?;
    let receipt = deployment.publish_and_commit(&slot, manifest, binding.receive_interval, cx)?;
    Ok((receipt.root, receipt.anchor))
}

fn read_record<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    identity: ContentDigest,
    is_intent: bool,
    expected_root: Option<ContentDigest>,
    cx: &ReplayCx<G>,
) -> Result<(Vec<u8>, ContentDigest), MetadataError> {
    metadata::admit(deployment, cx, "onvif_control:open")?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    if identity.algorithm() != DigestAlgorithm::Sha256 {
        return Err(MetadataError::InvalidBinding);
    }
    lifecycle::check_available(deployment, identity, is_intent, [identity], cx)?;
    let slot = slot(identity, is_intent)?;
    if deployment.publisher().is_broken_slot(&slot) {
        return Err(MetadataError::Custody);
    }
    let visible = deployment
        .publisher()
        .root(&slot)
        .ok_or(MetadataError::Unavailable)?;
    if visible.state != LocalPublicationState::Durable
        || expected_root.is_some_and(|root| root != visible.root)
    {
        return Err(MetadataError::Custody);
    }
    lifecycle::check_available(deployment, identity, is_intent, [visible.root], cx)?;
    deployment
        .publisher()
        .require_durable_record(&slot)
        .map_err(|_| MetadataError::Custody)?;
    let encoded = metadata::read(deployment, identity, MAX_CONTROL_RECORD_BYTES, cx)?;
    Ok((encoded, visible.root))
}

fn verify_manifest<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    identity: ContentDigest,
    is_intent: bool,
    manifest: &ObjectManifest,
    visible_root: ContentDigest,
    cx: &ReplayCx<G>,
) -> Result<(), MetadataError> {
    lifecycle::check_available(
        deployment,
        identity,
        is_intent,
        std::iter::once(manifest.root()).chain(manifest.children().iter().copied()),
        cx,
    )?;
    if manifest.root() != visible_root
        || metadata::read(deployment, visible_root, MAX_CONTROL_RECORD_BYTES, cx)?
            != manifest.canonical_bytes()
    {
        return Err(MetadataError::Custody);
    }
    Ok(())
}

fn finish_read<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    cx: &ReplayCx<G>,
) -> Result<(), MetadataError> {
    deployment
        .publisher()
        .require_durable_record(slot)
        .map_err(|_| MetadataError::Custody)?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    metadata::checkpoint(cx, "onvif_control:verified")
}

fn slot(identity: ContentDigest, is_intent: bool) -> Result<SlotName, MetadataError> {
    let prefix = if is_intent {
        "onvif-create-intent"
    } else {
        "onvif-subscription"
    };
    SlotName::parse(&format!("{prefix}-{}", &identity.to_text()[7..]))
        .map_err(|_| MetadataError::InvalidBinding)
}

fn intent_manifest(identity: ContentDigest) -> Result<ObjectManifest, MetadataError> {
    ObjectManifest::new(slot(identity, true)?.as_str(), vec![identity], None)
        .map_err(crate::ReferenceError::from)
        .map_err(Into::into)
}

fn created_manifest(
    identity: ContentDigest,
    record: &codec::CreatedRecord,
    intent: &RetainedCreateIntent,
) -> Result<ObjectManifest, MetadataError> {
    let mut children = vec![
        identity,
        record.source,
        intent.identity(),
        intent.publication_root(),
    ];
    children.sort_unstable();
    children.dedup();
    ObjectManifest::new(slot(identity, false)?.as_str(), children, None)
        .map_err(crate::ReferenceError::from)
        .map_err(Into::into)
}
