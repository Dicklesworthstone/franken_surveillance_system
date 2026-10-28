#![forbid(unsafe_code)]
//! Explicitly finite renewal intent and complete response custody, including rejected replies.
//! Historical records never grant permission to repeat an ambiguous Renew or extend a session.

use std::fmt;

use fss_core::{CanonicalEncode, CaptureInterval, ContentDigest, LedgerAnchor, TimestampNs};
use fss_object::ObjectManifest;

use super::{
    RetainedSubscription, admit_write, codec as parent_codec, created_manifest, finish_read,
    intent_manifest as create_intent_manifest, publish, read_record, slot, verify_manifest,
};
use crate::adapter_replay::ReplayAdmission;
use crate::onvif::http::HttpRoute;
use crate::onvif::metadata::{self, MAX_SOURCE_BYTES, MetadataError};
use crate::onvif::pullpoint::{MAX_RENEWALS, MAX_SESSION_NS};
use crate::onvif::wire::{
    PullPointLease, parse_renew_response, renew_pull_point_request, require_relates_to,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Frozen pre-dispatch renewal intent format.
pub const RENEW_INTENT_DOMAIN: &str = "fss.onvif_pullpoint_renew_intent.v1";
/// Frozen complete renewal response format, including unusable responses.
pub const RENEWED_DOMAIN: &str = "fss.onvif_pullpoint_renewed.v1";
/// Last cancellable admission before an intent publication.
pub const STAGE_RENEW_INTENT_PUBLISH: &str = "onvif_control:renew_intent_publish";
/// Last cancellable admission before complete renewal response publication.
pub const STAGE_RENEWED_PUBLISH: &str = "onvif_control:renewed_publish";

/// One live owner's finite renewal request, tied to the original retained Create.
#[derive(Clone, Eq, PartialEq)]
pub struct RenewIntentBinding {
    /// Exact original approved subscription route, never a new server-returned route.
    pub route: HttpRoute,
    /// Fresh logical request identity; exact retries of custody do not authorize dispatch.
    pub message_id: String,
    /// Original monotonic request admission, before intent storage.
    pub started_ns: u64,
    /// Explicit deployment-clock admission point, not a received-response timestamp.
    pub receive_time: TimestampNs,
    /// Requested finite lease, no greater than the original approved lifetime.
    pub lifetime_seconds: u32,
    /// Zero-based bounded renewal attempt in this capture.
    pub renewal_index: u32,
}
impl RenewIntentBinding {
    /// Validate original route, owner scope, finite lease and exact logical request.
    pub fn validate(&self, created: &RetainedSubscription) -> Result<(), MetadataError> {
        let elapsed = self
            .started_ns
            .checked_sub(created.binding().started_ns)
            .filter(|elapsed| *elapsed <= MAX_SESSION_NS)
            .ok_or(MetadataError::InvalidBinding)?;
        let receive_time = created
            .binding()
            .source
            .receive_interval
            .earliest
            .0
            .checked_add(i128::from(elapsed))
            .ok_or(MetadataError::InvalidBinding)?;
        let expected = created
            .binding()
            .events
            .event_subscription(
                created.subscription().endpoint(),
                &created.binding().service_root,
            )
            .map_err(|_| MetadataError::InvalidBinding)?;
        if self.route.digest() != expected.digest()
            || self.message_id == created.binding().message_id
            || self.started_ns < created.completed_ns()
            || self.receive_time < created.receive_interval().latest
            || self.receive_time.0 != receive_time
            || self.lifetime_seconds > created.binding().lifetime_seconds
            || self.renewal_index >= MAX_RENEWALS
        {
            return Err(MetadataError::InvalidBinding);
        }
        renew_pull_point_request(created.subscription(), self.lifetime_seconds)?
            .with_message_id(&self.message_id)?;
        Ok(())
    }
    fn receive_interval(
        &self,
        completed_ns: Option<u64>,
    ) -> Result<CaptureInterval, MetadataError> {
        let elapsed = completed_ns
            .map(|completed| {
                completed
                    .checked_sub(self.started_ns)
                    .filter(|elapsed| *elapsed <= MAX_SESSION_NS)
                    .ok_or(MetadataError::InvalidBinding)
            })
            .transpose()?
            .unwrap_or(0);
        let end = self
            .receive_time
            .0
            .checked_add(i128::from(elapsed))
            .ok_or(MetadataError::InvalidBinding)?;
        Ok(CaptureInterval::new(self.receive_time, TimestampNs(end))?)
    }
}
impl fmt::Debug for RenewIntentBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenewIntentBinding")
            .field("route_digest", &self.route.digest())
            .field("started_ns", &self.started_ns)
            .field("lifetime_seconds", &self.lifetime_seconds)
            .field("renewal_index", &self.renewal_index)
            .finish_non_exhaustive()
    }
}

/// Complete HTTP-response observations. A body can be retained without a usable lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewOutcomeBinding {
    /// Monotonic complete response observation, absent if the live clock refused.
    pub completed_ns: Option<u64>,
    /// Whether client Digest proof was sent; this does not authenticate the camera.
    pub client_authenticated: bool,
    /// Complete final HTTP status; a non-200 response never extends the lease.
    pub http_status: u16,
    /// Whether the complete response declared application/soap+xml.
    pub soap_content_type: bool,
}

/// Durable pre-dispatch obligation. Cold opens and exact custody retries cannot resend it.
#[derive(Clone)]
pub struct RetainedRenewIntent {
    identity: ContentDigest,
    root: ContentDigest,
    record: codec::IntentRecord,
    subscription: RetainedSubscription,
    anchor: LedgerAnchor,
    newly_prepared: bool,
}
impl RetainedRenewIntent {
    /// Verify complete original Create and intent custody before exposing historical values.
    pub fn open<G: ReplayAdmission>(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx<G>,
    ) -> Result<Self, MetadataError> {
        let (bytes, root) = read_record(deployment, identity, false, expected_root, cx)?;
        let record = codec::decode_intent(&bytes)?;
        let subscription = RetainedSubscription::open(deployment, record.subscription, None, cx)?;
        record.binding.validate(&subscription)?;
        let manifest = intent_manifest(identity, &subscription)?;
        verify_manifest(deployment, identity, false, &manifest, root, cx)?;
        let mut binding = subscription.binding().source.clone();
        binding.receive_interval = record.binding.receive_interval(None)?;
        let anchor = metadata::check_publication(
            deployment,
            &slot(identity, false)?,
            &manifest,
            &binding,
            cx,
        )?;
        finish_read(deployment, &slot(identity, false)?, cx)?;
        Ok(Self {
            identity,
            root,
            record,
            subscription,
            anchor,
            newly_prepared: false,
        })
    }
    /// Exact immutable pre-dispatch intent identity.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact publication root, suitable for an independent cold pin.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// True only after this invocation's first publication, never a cold read or exact retry.
    pub const fn newly_prepared(&self) -> bool {
        self.newly_prepared
    }
    /// Original retained Create, including its private endpoint and source closure.
    pub fn subscription(&self) -> &RetainedSubscription {
        &self.subscription
    }
    /// Frozen original request; no current I/O grant is implied.
    pub fn binding(&self) -> &RenewIntentBinding {
        &self.record.binding
    }
    /// Original ledger anchor.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}
impl fmt::Debug for RetainedRenewIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedRenewIntent")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("subscription", &self.subscription.identity())
            .finish_non_exhaustive()
    }
}

/// Historical complete response, with an optional strictly parsed device-declared interval.
#[derive(Clone)]
pub struct RetainedRenewal {
    identity: ContentDigest,
    root: ContentDigest,
    record: codec::OutcomeRecord,
    intent: RetainedRenewIntent,
    source: Vec<u8>,
    lease: Option<PullPointLease>,
    receive_interval: CaptureInterval,
    anchor: LedgerAnchor,
}
impl RetainedRenewal {
    /// Rehash complete source and parent closure and reproduce usable/unknown classification.
    pub fn open<G: ReplayAdmission>(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx<G>,
    ) -> Result<Self, MetadataError> {
        let (bytes, root) = read_record(deployment, identity, false, expected_root, cx)?;
        let record = codec::decode_outcome(&bytes)?;
        let intent = RetainedRenewIntent::open(deployment, record.intent, None, cx)?;
        let manifest = outcome_manifest(identity, &record, &intent)?;
        verify_manifest(deployment, identity, false, &manifest, root, cx)?;
        let source = metadata::read(deployment, record.source, record.source_bytes, cx)?;
        let (lease, receive_interval) = validate_outcome(&intent, &record, &source)?;
        let mut binding = intent.subscription().binding().source.clone();
        binding.receive_interval = receive_interval;
        let anchor = metadata::check_publication(
            deployment,
            &slot(identity, false)?,
            &manifest,
            &binding,
            cx,
        )?;
        finish_read(deployment, &slot(identity, false)?, cx)?;
        Ok(Self {
            identity,
            root,
            record,
            intent,
            source,
            lease,
            receive_interval,
            anchor,
        })
    }
    /// Exact immutable complete-response identity.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact durable response root.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Verified parent intent; its original existence alone implies no successful renewal.
    pub fn intent(&self) -> &RetainedRenewIntent {
        &self.intent
    }
    /// Exact observed response metadata, including uncertain clock completion.
    pub fn binding(&self) -> &RenewOutcomeBinding {
        &self.record.binding
    }
    /// Complete private response bytes, including rejected/unsupported content.
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    /// Exact response digest.
    pub const fn source_digest(&self) -> ContentDigest {
        self.record.source
    }
    /// Exact response length, including an invalid empty HTTP body.
    pub const fn source_bytes(&self) -> usize {
        self.record.source_bytes
    }
    /// A correlated successful response interval, never current authority or future-state proof.
    /// Missing clock completion, wrong HTTP type/status, malformed and mismatched replies are None.
    pub fn lease(&self) -> Option<&PullPointLease> {
        self.lease.as_ref()
    }
    /// Explicit local interval; without clock completion this remains the admission point.
    pub const fn receive_interval(&self) -> CaptureInterval {
        self.receive_interval
    }
    /// Original immutable custody anchor.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}
impl fmt::Debug for RetainedRenewal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedRenewal")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("intent", &self.intent.identity())
            .field("source_bytes", &self.source.len())
            .field("usable_lease", &self.lease.is_some())
            .finish_non_exhaustive()
    }
}

/// Persist one finite request before any network dispatch. Exact storage retry is not resend.
pub fn prepare_renew<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    subscription: &RetainedSubscription,
    binding: RenewIntentBinding,
    cx: &ReplayCx<G>,
) -> Result<RetainedRenewIntent, MetadataError> {
    admit_write(deployment, cx)?;
    let subscription = RetainedSubscription::open(
        deployment,
        subscription.identity(),
        Some(subscription.publication_root()),
        cx,
    )?;
    binding.validate(&subscription)?;
    let record = codec::IntentRecord {
        subscription: subscription.identity(),
        binding,
    };
    let encoded = codec::encode_intent(&record)?;
    let identity = ContentDigest::sha256(&encoded);
    let manifest = intent_manifest(identity, &subscription)?;
    let newly_prepared = deployment
        .publisher()
        .root(&slot(identity, false)?)
        .is_none();
    let mut objects = parent_objects(&subscription)?;
    objects.push(encoded);
    let refs: Vec<_> = objects.iter().map(Vec::as_slice).collect();
    let mut source_binding = subscription.binding().source.clone();
    source_binding.receive_interval = record.binding.receive_interval(None)?;
    let (root, anchor) = publish(
        deployment,
        identity,
        &manifest,
        &source_binding,
        &refs,
        false,
        STAGE_RENEW_INTENT_PUBLISH,
        cx,
    )?;
    let retained = RetainedRenewIntent {
        identity,
        root,
        record,
        subscription,
        anchor,
        newly_prepared,
    };
    cx.checkpoint_post_commit("onvif_control:renew_intent_committed");
    Ok(retained)
}

/// Retain a complete response even when it cannot acknowledge the renewal.
/// Any transport loss before a complete response leaves only the immutable intent unresolved.
pub fn retain_renewal<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    intent: &RetainedRenewIntent,
    binding: RenewOutcomeBinding,
    source: &[u8],
    cx: &ReplayCx<G>,
) -> Result<RetainedRenewal, MetadataError> {
    admit_write(deployment, cx)?;
    let intent = RetainedRenewIntent::open(
        deployment,
        intent.identity(),
        Some(intent.publication_root()),
        cx,
    )?;
    let record = codec::OutcomeRecord {
        intent: intent.identity(),
        binding,
        source: ContentDigest::sha256(source),
        source_bytes: source.len(),
    };
    let (lease, receive_interval) = validate_outcome(&intent, &record, source)?;
    let encoded = codec::encode_outcome(&record)?;
    let identity = ContentDigest::sha256(&encoded);
    let manifest = outcome_manifest(identity, &record, &intent)?;
    let mut objects = parent_objects(intent.subscription())?;
    objects.push(codec::encode_intent(&intent.record)?);
    objects.push(intent_manifest(intent.identity(), intent.subscription())?.canonical_bytes());
    objects.push(source.to_vec());
    objects.push(encoded);
    let refs: Vec<_> = objects.iter().map(Vec::as_slice).collect();
    let mut source_binding = intent.subscription().binding().source.clone();
    source_binding.receive_interval = receive_interval;
    let (root, anchor) = publish(
        deployment,
        identity,
        &manifest,
        &source_binding,
        &refs,
        false,
        STAGE_RENEWED_PUBLISH,
        cx,
    )?;
    let retained = RetainedRenewal {
        identity,
        root,
        record,
        intent,
        source: source.to_vec(),
        lease,
        receive_interval,
        anchor,
    };
    cx.checkpoint_post_commit("onvif_control:renewed_committed");
    Ok(retained)
}

fn validate_outcome(
    intent: &RetainedRenewIntent,
    record: &codec::OutcomeRecord,
    source: &[u8],
) -> Result<(Option<PullPointLease>, CaptureInterval), MetadataError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    if source.len() != record.source_bytes || ContentDigest::sha256(source) != record.source {
        return Err(MetadataError::Custody);
    }
    if !(100..=599).contains(&record.binding.http_status) {
        return Err(MetadataError::InvalidBinding);
    }
    if record.binding.completed_ns.is_some_and(|completed| {
        completed.saturating_sub(intent.subscription().binding().started_ns) > MAX_SESSION_NS
    }) {
        return Err(MetadataError::InvalidBinding);
    }
    let interval = intent
        .binding()
        .receive_interval(record.binding.completed_ns)?;
    let lease = if record.binding.completed_ns.is_some()
        && record.binding.http_status == 200
        && record.binding.soap_content_type
    {
        require_relates_to(source, &intent.binding().message_id)
            .and_then(|()| parse_renew_response(source))
            .ok()
    } else {
        None
    };
    Ok((lease, interval))
}
fn parent_children(created: &RetainedSubscription) -> Vec<ContentDigest> {
    vec![
        created.identity(),
        created.publication_root(),
        created.source_digest(),
        created.intent().identity(),
        created.intent().publication_root(),
    ]
}
fn intent_manifest(
    identity: ContentDigest,
    created: &RetainedSubscription,
) -> Result<ObjectManifest, MetadataError> {
    let mut children = parent_children(created);
    children.push(identity);
    manifest(identity, children)
}
fn outcome_manifest(
    identity: ContentDigest,
    record: &codec::OutcomeRecord,
    intent: &RetainedRenewIntent,
) -> Result<ObjectManifest, MetadataError> {
    let mut children = parent_children(intent.subscription());
    children.extend([
        identity,
        record.source,
        intent.identity(),
        intent.publication_root(),
    ]);
    manifest(identity, children)
}
fn manifest(
    identity: ContentDigest,
    mut children: Vec<ContentDigest>,
) -> Result<ObjectManifest, MetadataError> {
    children.sort_unstable();
    children.dedup();
    ObjectManifest::new(slot(identity, false)?.as_str(), children, None)
        .map_err(crate::ReferenceError::from)
        .map_err(Into::into)
}
fn parent_objects(created: &RetainedSubscription) -> Result<Vec<Vec<u8>>, MetadataError> {
    Ok(vec![
        parent_codec::encode_created(&created.record)?,
        created_manifest(created.identity(), &created.record, &created.intent)?.canonical_bytes(),
        created.source().to_vec(),
        parent_codec::encode_intent(&created.intent.record)?,
        create_intent_manifest(created.intent.identity())?.canonical_bytes(),
    ])
}

mod codec;
