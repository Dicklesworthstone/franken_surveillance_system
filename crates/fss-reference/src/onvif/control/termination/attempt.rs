#![forbid(unsafe_code)]
//! Pre-dispatch cleanup obligations and complete raw outcomes in the existing control graph.
//! Historical attempts never grant permission to resend or recover a network capability.

mod codec;

use std::fmt;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, DigestAlgorithm,
    LedgerAnchor, TimestampNs,
};
use fss_object::ObjectManifest;

use crate::adapter_replay::ReplayAdmission;
use crate::onvif::control::{
    ControlDescriptor, ControlKind, RetainedSubscription, RetainedUnsubscribe, admit_write,
    codec as parent_codec, created_manifest, finish_read,
    intent_manifest as create_intent_manifest, publish, read_record, slot, verify_manifest,
};
use crate::onvif::http::HttpRoute;
use crate::onvif::metadata::{self, MAX_SOURCE_BYTES, MetadataError};
use crate::onvif::pullpoint::MAX_SESSION_NS;
use crate::onvif::wire::{
    parse_unsubscribe_response, require_relates_to, unsubscribe_pull_point_request,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Frozen pre-dispatch cleanup format, independent of the unchanged successful terminal v1.
pub const UNSUBSCRIBE_INTENT_DOMAIN: &str = "fss.onvif_pullpoint_unsubscribe_intent.v1";
/// Frozen complete cleanup outcome, including rejected, malformed, and clock-uncertain bodies.
pub const UNSUBSCRIBE_OUTCOME_DOMAIN: &str = "fss.onvif_pullpoint_unsubscribe_outcome.v1";
/// Last cancellable admission before cleanup intent publication.
pub const STAGE_UNSUBSCRIBE_INTENT_PUBLISH: &str = "onvif_control:unsubscribe_intent_publish";
/// Last cancellable admission before raw cleanup outcome publication.
pub const STAGE_UNSUBSCRIBE_OUTCOME_PUBLISH: &str = "onvif_control:unsubscribe_outcome_publish";
const MAX_CLEANUP_ATTEMPTS: usize = 64;

/// One independently authorized cleanup request and the exact current control-history fence.
#[derive(Clone, Eq, PartialEq)]
pub struct UnsubscribeIntentBinding {
    /// Current owner-approved exact subscription route, including fresh approval when retried.
    pub route: HttpRoute,
    /// Exact original Create request identity from verified parent custody.
    pub create_message_id: String,
    /// Fresh logical Unsubscribe identity; custody retry does not authorize redispatch.
    pub message_id: String,
    /// SHA-256 of the exact Unsubscribe SOAP body, including EPR parameters and fresh ID.
    pub request_digest: ContentDigest,
    /// Current owner's monotonic request admission, unrelated to previous processes.
    pub started_ns: u64,
    /// Explicit deployment-clock admission point.
    pub receive_time: TimestampNs,
    /// Exact verified control-history witness selected before this intent is prepared.
    pub expected_control: ContentDigest,
}

impl UnsubscribeIntentBinding {
    /// Validate parent attribution, original EPR parameters, route scope and bounded request.
    pub fn validate(&self, created: &RetainedSubscription) -> Result<(), MetadataError> {
        let expected = created
            .binding()
            .events
            .event_subscription(
                created.subscription().endpoint(),
                &created.binding().service_root,
            )
            .map_err(|_| MetadataError::InvalidBinding)?;
        if !self.route.is_event_subscription()
            || self.route.plaintext_approval().algorithm() != DigestAlgorithm::Sha256
            || self.route.peer() != expected.peer()
            || self.route.authority() != expected.authority()
            || self.route.target() != expected.target()
            || self.route.generation() != expected.generation()
            || self.create_message_id != created.binding().message_id
            || self.message_id == self.create_message_id
            || self.receive_time < created.receive_interval().latest
            || self.expected_control.algorithm() != DigestAlgorithm::Sha256
            || self.expected_control.bytes() == [0; 32]
            || self.request_digest.algorithm() != DigestAlgorithm::Sha256
        {
            return Err(MetadataError::InvalidBinding);
        }
        let request = unsubscribe_pull_point_request(created.subscription())?
            .with_message_id(&self.message_id)?;
        if ContentDigest::sha256(request.body()) != self.request_digest {
            return Err(MetadataError::InvalidBinding);
        }
        CaptureInterval::new(self.receive_time, self.receive_time)?;
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

impl fmt::Debug for UnsubscribeIntentBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnsubscribeIntentBinding")
            .field("route_digest", &self.route.digest())
            .field("request_digest", &self.request_digest)
            .field("expected_control", &self.expected_control)
            .field("started_ns", &self.started_ns)
            .finish_non_exhaustive()
    }
}

/// Complete final HTTP observation. Local clock uncertainty never discards the raw body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsubscribeOutcomeBinding {
    /// Monotonic completion, absent if the current owner's clock refused.
    pub completed_ns: Option<u64>,
    /// Whether a client Digest proof was sent, not server authentication.
    pub client_authenticated: bool,
    /// Complete final HTTP status.
    pub http_status: u16,
    /// Whether the response declared application/soap+xml.
    pub soap_content_type: bool,
}

/// Verified current cleanup history. A missing terminal receipt never proves a remote lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupStatus {
    /// Exact complete linked control state; unrelated authority appends do not alter it.
    pub witness: ContentDigest,
    /// Verified successful v1 receipt or successful raw outcome, if retained.
    pub terminal: Option<ControlDescriptor>,
    /// Latest durable cleanup intent, including attempts with no complete outcome.
    pub latest_intent: Option<ControlDescriptor>,
    /// Number of retained cleanup attempts in this control graph.
    pub attempts: usize,
    attempt_bindings: Vec<(ContentDigest, ContentDigest)>,
}

/// Discover terminal observations and an exact current attempt fence under live read authority.
/// Every catalog record is fully verified. Missing/damaged custody is never treated as absence.
pub fn inspect_cleanup<G: ReplayAdmission>(
    deployment: &ReferenceDeployment,
    created: &RetainedSubscription,
    cx: &ReplayCx<G>,
) -> Result<CleanupStatus, MetadataError> {
    let created = RetainedSubscription::open(
        deployment,
        created.identity(),
        Some(created.publication_root()),
        cx,
    )?;
    let catalog =
        crate::onvif::control::catalog::list_cleanup_control(deployment, created.identity(), cx)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_pullpoint_cleanup_state.v1");
    e.text(deployment.site_lineage());
    e.u64(deployment.current_anchor().ledger_epoch);
    e.digest(created.identity());
    e.digest(created.publication_root());
    let mut terminal = None;
    let mut latest_intent = None;
    let mut attempts = 0;
    let mut attempt_bindings = Vec::new();
    for descriptor in catalog
        .into_iter()
        .filter(|entry| entry.subscription_identity == Some(created.identity()))
    {
        metadata::checkpoint(cx, "onvif_control:cleanup_state")?;
        e.digest(descriptor.identity);
        e.digest(descriptor.root);
        e.u64(descriptor.authority_sequence);
        match descriptor.kind {
            ControlKind::Unsubscribed => {
                RetainedUnsubscribe::open(
                    deployment,
                    descriptor.identity,
                    Some(descriptor.root),
                    cx,
                )?;
                terminal = Some(descriptor);
            }
            ControlKind::UnsubscribeIntent => {
                attempts += 1;
                if attempts > MAX_CLEANUP_ATTEMPTS {
                    return Err(MetadataError::Limit);
                }
                let intent = RetainedUnsubscribeIntent::open(
                    deployment,
                    descriptor.identity,
                    Some(descriptor.root),
                    cx,
                )?;
                attempt_bindings.push((
                    ContentDigest::sha256(intent.binding().message_id.as_bytes()),
                    intent.binding().route.plaintext_approval(),
                ));
                latest_intent = Some(descriptor);
            }
            ControlKind::UnsubscribeOutcome => {
                let outcome = RetainedUnsubscribeOutcome::open(
                    deployment,
                    descriptor.identity,
                    Some(descriptor.root),
                    cx,
                )?;
                if outcome.success_observed() {
                    terminal = Some(descriptor);
                }
            }
            _ => {}
        }
    }
    Ok(CleanupStatus {
        witness: ContentDigest::sha256(&e.finish_checked()?),
        terminal,
        latest_intent,
        attempts,
        attempt_bindings,
    })
}

/// Durable cleanup obligation. Cold reads and exact storage retries never permit a resend.
#[derive(Clone)]
pub struct RetainedUnsubscribeIntent {
    identity: ContentDigest,
    root: ContentDigest,
    record: codec::IntentRecord,
    subscription: RetainedSubscription,
    anchor: LedgerAnchor,
    newly_prepared: bool,
}

impl RetainedUnsubscribeIntent {
    /// Reverify the exact parent and immutable request without repairing source custody.
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
    /// Immutable request receipt identity.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact durable publication root.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// True only after first publication in this invocation, never a read or exact retry.
    pub const fn newly_prepared(&self) -> bool {
        self.newly_prepared
    }
    /// Verified original Create, not a current network grant.
    pub fn subscription(&self) -> &RetainedSubscription {
        &self.subscription
    }
    /// Exact retained request and selected control-state fence.
    pub fn binding(&self) -> &UnsubscribeIntentBinding {
        &self.record.binding
    }
    /// Original immutable custody anchor.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}
impl fmt::Debug for RetainedUnsubscribeIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedUnsubscribeIntent")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("subscription", &self.subscription.identity())
            .finish_non_exhaustive()
    }
}

/// Complete cleanup response custody, including refused, malformed, empty or untimed bodies.
#[derive(Clone)]
pub struct RetainedUnsubscribeOutcome {
    identity: ContentDigest,
    root: ContentDigest,
    record: codec::OutcomeRecord,
    intent: RetainedUnsubscribeIntent,
    source: Vec<u8>,
    success_observed: bool,
    receive_interval: CaptureInterval,
    anchor: LedgerAnchor,
}
impl RetainedUnsubscribeOutcome {
    /// Rehash source and parent closure, reproducing the historical success classification.
    pub fn open<G: ReplayAdmission>(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx<G>,
    ) -> Result<Self, MetadataError> {
        let (bytes, root) = read_record(deployment, identity, false, expected_root, cx)?;
        let record = codec::decode_outcome(&bytes)?;
        let intent = RetainedUnsubscribeIntent::open(deployment, record.intent, None, cx)?;
        let manifest = outcome_manifest(identity, &record, &intent)?;
        verify_manifest(deployment, identity, false, &manifest, root, cx)?;
        let source = metadata::read(deployment, record.source, record.source_bytes, cx)?;
        let (success_observed, receive_interval) = validate_outcome(&intent, &record, &source)?;
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
            success_observed,
            receive_interval,
            anchor,
        })
    }
    /// Immutable complete-response receipt identity.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact durable response root.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Verified pre-dispatch cleanup obligation.
    pub fn intent(&self) -> &RetainedUnsubscribeIntent {
        &self.intent
    }
    /// Exact HTTP observations, preserving missing completion time separately.
    pub fn binding(&self) -> &UnsubscribeOutcomeBinding {
        &self.record.binding
    }
    /// Complete private raw response body, never suitable for diagnostic logs.
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    /// Exact raw-body digest.
    pub const fn source_digest(&self) -> ContentDigest {
        self.record.source
    }
    /// Raw-body length, including empty refused responses.
    pub const fn source_bytes(&self) -> usize {
        self.record.source_bytes
    }
    /// HTTP200 SOAP with exact required correlation and valid UnsubscribeResponse was observed.
    /// A missing local completion clock does not erase this acknowledgment or permit a resend.
    pub const fn success_observed(&self) -> bool {
        self.success_observed
    }
    /// Explicit local interval; missing completion leaves the admission point unchanged.
    pub const fn receive_interval(&self) -> CaptureInterval {
        self.receive_interval
    }
    /// Original immutable custody anchor.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}
impl fmt::Debug for RetainedUnsubscribeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedUnsubscribeOutcome")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("intent", &self.intent.identity())
            .field("source_bytes", &self.source.len())
            .field("success_observed", &self.success_observed)
            .finish_non_exhaustive()
    }
}

/// Publish an exact cleanup intent against current verified state, before any dispatch.
/// A changed state, known terminal acknowledgment, reused request ID or old retry approval
/// refuses before staging. Existing exact custody can resume but never becomes dispatchable.
pub fn prepare_unsubscribe<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    subscription: &RetainedSubscription,
    binding: UnsubscribeIntentBinding,
    cx: &ReplayCx<G>,
) -> Result<RetainedUnsubscribeIntent, MetadataError> {
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
    if newly_prepared {
        let status = inspect_cleanup(deployment, &subscription, cx)?;
        if status.terminal.is_some() || status.witness != record.binding.expected_control {
            return Err(MetadataError::InvalidBinding);
        }
        if status.attempts >= MAX_CLEANUP_ATTEMPTS {
            return Err(MetadataError::Limit);
        }
        for (message_id, approval) in status.attempt_bindings {
            if message_id == ContentDigest::sha256(record.binding.message_id.as_bytes())
                || approval == record.binding.route.plaintext_approval()
            {
                return Err(MetadataError::InvalidBinding);
            }
        }
    }
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
        STAGE_UNSUBSCRIBE_INTENT_PUBLISH,
        cx,
    )?;
    let retained = RetainedUnsubscribeIntent {
        identity,
        root,
        record,
        subscription,
        anchor,
        newly_prepared,
    };
    cx.checkpoint_post_commit("onvif_control:unsubscribe_intent_committed");
    Ok(retained)
}

/// Retain any complete final HTTP response before interpreting cleanup success.
/// A transport loss before a complete response leaves the immutable intent unresolved.
pub fn retain_unsubscribe_outcome<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    intent: &RetainedUnsubscribeIntent,
    binding: UnsubscribeOutcomeBinding,
    source: &[u8],
    cx: &ReplayCx<G>,
) -> Result<RetainedUnsubscribeOutcome, MetadataError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    admit_write(deployment, cx)?;
    let intent = RetainedUnsubscribeIntent::open(
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
    let (success_observed, receive_interval) = validate_outcome(&intent, &record, source)?;
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
        STAGE_UNSUBSCRIBE_OUTCOME_PUBLISH,
        cx,
    )?;
    let retained = RetainedUnsubscribeOutcome {
        identity,
        root,
        record,
        intent,
        source: source.to_vec(),
        success_observed,
        receive_interval,
        anchor,
    };
    cx.checkpoint_post_commit("onvif_control:unsubscribe_outcome_committed");
    Ok(retained)
}

fn validate_outcome(
    intent: &RetainedUnsubscribeIntent,
    record: &codec::OutcomeRecord,
    source: &[u8],
) -> Result<(bool, CaptureInterval), MetadataError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    if source.len() != record.source_bytes || ContentDigest::sha256(source) != record.source {
        return Err(MetadataError::Custody);
    }
    if !(100..=599).contains(&record.binding.http_status) {
        return Err(MetadataError::InvalidBinding);
    }
    let interval = intent
        .binding()
        .receive_interval(record.binding.completed_ns)?;
    let success = record.binding.http_status == 200
        && record.binding.soap_content_type
        && require_relates_to(source, &intent.binding().message_id)
            .and_then(|()| parse_unsubscribe_response(source))
            .is_ok();
    Ok((success, interval))
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
    intent: &RetainedUnsubscribeIntent,
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
