#![forbid(unsafe_code)]
//! Historical, source-backed confirmation of one explicitly authorized Unsubscribe.
//!
//! A retained EPR or prior approval grants no new network authority. The caller
//! supplies the currently admitted exact route, independent receive interval and
//! fresh logical request ID. A receipt proves the observed response, not future
//! device behavior or that the camera could never reuse an endpoint.

use std::fmt;
use std::net::SocketAddr;

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    DigestAlgorithm, LedgerAnchor, TimestampNs,
};
use fss_object::ObjectManifest;

use super::{
    MAX_CONTROL_RECORD_BYTES, PARSER_GENERATION, RetainedSubscription, admit_write, codec,
    created_manifest, finish_read, intent_manifest, publish, read_record, slot, verify_manifest,
};
use crate::adapter_replay::ReplayAdmission;
use crate::onvif::http::HttpRoute;
use crate::onvif::metadata::{self, MAX_SOURCE_BYTES, MetadataError};
use crate::onvif::pullpoint::MAX_SESSION_NS;
use crate::onvif::wire::{
    parse_unsubscribe_response, require_relates_to, unsubscribe_pull_point_request,
};
use crate::{ReferenceDeployment, ReplayCx};

/// Frozen canonical terminal-response format.
pub const UNSUBSCRIBED_DOMAIN: &str = "fss.onvif_pullpoint_unsubscribed.v1";
/// Last cancellable point before publishing the observed cleanup receipt.
pub const STAGE_UNSUBSCRIBED_PUBLISH: &str = "onvif_control:unsubscribed_publish";

/// Independently current owner context for the cleanup request.
///
/// Monotonic coordinates may belong to a new process; only this operation's span
/// is compared. The explicit receive interval remains in the deployment clock.
#[derive(Clone, Eq, PartialEq)]
pub struct UnsubscribeBinding {
    /// Exact current event-capable route, including its current explicit approval.
    pub route: HttpRoute,
    /// Fresh logical Unsubscribe identity, distinct from the original Create ID.
    pub message_id: String,
    /// Monotonic cleanup admission time.
    pub started_ns: u64,
    /// Monotonic complete response time.
    pub completed_ns: u64,
    /// Independently declared receive interval with the exact observed span.
    pub receive_interval: CaptureInterval,
    /// Whether a client Digest proof was sent; no server-identity proof is implied.
    pub client_authenticated: bool,
}

impl UnsubscribeBinding {
    /// Validate bounds and exact retained endpoint without performing I/O.
    pub fn validate(&self, created: &RetainedSubscription) -> Result<(), MetadataError> {
        let expected = created
            .binding()
            .events
            .event_subscription(
                created.subscription().endpoint(),
                &created.binding().service_root,
            )
            .map_err(|_| MetadataError::InvalidBinding)?;
        let elapsed = self
            .completed_ns
            .checked_sub(self.started_ns)
            .filter(|span| *span <= MAX_SESSION_NS)
            .ok_or(MetadataError::InvalidBinding)?;
        let span = self
            .receive_interval
            .latest
            .0
            .checked_sub(self.receive_interval.earliest.0)
            .ok_or(MetadataError::InvalidBinding)?;
        if !self.route.is_event_subscription()
            || self.route.plaintext_approval().algorithm() != DigestAlgorithm::Sha256
            || self.route.peer() != expected.peer()
            || self.route.authority() != expected.authority()
            || self.route.target() != expected.target()
            || self.route.generation() != expected.generation()
            || self.message_id == created.binding().message_id
            || self.receive_interval.earliest < created.receive_interval().latest
            || span != i128::from(elapsed)
        {
            return Err(MetadataError::InvalidBinding);
        }
        CaptureInterval::new(self.receive_interval.earliest, self.receive_interval.latest)?;
        unsubscribe_pull_point_request(created.subscription())
            .and_then(|request| request.with_message_id(&self.message_id))
            .map_err(|_| MetadataError::InvalidBinding)?;
        Ok(())
    }
}
impl fmt::Debug for UnsubscribeBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnsubscribeBinding")
            .field("route_digest", &self.route.digest())
            .field("started_ns", &self.started_ns)
            .field("completed_ns", &self.completed_ns)
            .field("receive_interval", &self.receive_interval)
            .field("client_authenticated", &self.client_authenticated)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct Record {
    subscription: ContentDigest,
    binding: UnsubscribeBinding,
    source: ContentDigest,
    source_bytes: usize,
}

/// Exact historical cleanup observation with immutable parent and source custody.
#[derive(Clone)]
pub struct RetainedUnsubscribe {
    identity: ContentDigest,
    root: ContentDigest,
    record: Record,
    subscription: RetainedSubscription,
    source: Vec<u8>,
    anchor: LedgerAnchor,
}

impl RetainedUnsubscribe {
    /// Rehash and reparse retained cleanup, Create and intent sources after restart.
    pub fn open<G: ReplayAdmission>(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx<G>,
    ) -> Result<Self, MetadataError> {
        let (encoded, visible_root) = read_record(deployment, identity, false, expected_root, cx)?;
        let record = decode(&encoded)?;
        let subscription = RetainedSubscription::open(deployment, record.subscription, None, cx)?;
        record.binding.validate(&subscription)?;
        let manifest = manifest(identity, &record, &subscription)?;
        verify_manifest(deployment, identity, false, &manifest, visible_root, cx)?;
        let source = metadata::read(deployment, record.source, record.source_bytes, cx)?;
        validate_source(&record, &source)?;
        let mut binding = subscription.binding().source.clone();
        binding.receive_interval = record.binding.receive_interval;
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
            root: visible_root,
            record,
            subscription,
            source,
            anchor,
        })
    }

    /// Exact immutable cleanup receipt identity.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Durable root containing cleanup plus its Create/intent source closure.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Exact prior observed subscription receipt.
    pub const fn subscription_identity(&self) -> ContentDigest {
        self.record.subscription
    }
    /// Verified original Create receipt; neither it nor this receipt grants fresh I/O.
    pub fn subscription(&self) -> &RetainedSubscription {
        &self.subscription
    }
    /// Original independently admitted cleanup context.
    pub fn binding(&self) -> &UnsubscribeBinding {
        &self.record.binding
    }
    /// Exact complete Unsubscribe SOAP; raw headers can contain private vendor values.
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    /// Exact source digest.
    pub const fn source_digest(&self) -> ContentDigest {
        self.record.source
    }
    /// Exact source byte length.
    pub const fn source_bytes(&self) -> usize {
        self.record.source_bytes
    }
    /// Original cleanup-custody anchor, stable across exact storage retries.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}
impl fmt::Debug for RetainedUnsubscribe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedUnsubscribe")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("subscription", &self.record.subscription)
            .field("source_digest", &self.record.source)
            .field("source_bytes", &self.record.source_bytes)
            .finish_non_exhaustive()
    }
}

/// Retain one successful, exactly correlated cleanup observation.
///
/// The source and parent closure are completely checked before staging. Exact
/// retries may finish root-to-ledger linkage but never repair damaged custody.
pub fn retain_unsubscribed<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    subscription: &RetainedSubscription,
    binding: UnsubscribeBinding,
    source: &[u8],
    cx: &ReplayCx<G>,
) -> Result<RetainedUnsubscribe, MetadataError> {
    admit_write(deployment, cx)?;
    let subscription = RetainedSubscription::open(
        deployment,
        subscription.identity(),
        Some(subscription.publication_root()),
        cx,
    )?;
    binding.validate(&subscription)?;
    let record = Record {
        subscription: subscription.identity(),
        binding,
        source: ContentDigest::sha256(source),
        source_bytes: source.len(),
    };
    validate_source(&record, source)?;
    let encoded = encode(&record)?;
    let identity = ContentDigest::sha256(&encoded);
    let manifest = manifest(identity, &record, &subscription)?;
    let parent_encoded = codec::encode_created(&subscription.record)?;
    let parent_manifest = created_manifest(
        subscription.identity(),
        &subscription.record,
        &subscription.intent,
    )?
    .canonical_bytes();
    let intent_encoded = codec::encode_intent(&subscription.intent.record)?;
    let intent_manifest = intent_manifest(subscription.intent.identity())?.canonical_bytes();
    let retained_source = source.to_vec();
    let mut source_binding = subscription.binding().source.clone();
    source_binding.receive_interval = record.binding.receive_interval;
    let (root, anchor) = publish(
        deployment,
        identity,
        &manifest,
        &source_binding,
        &[
            encoded.as_slice(),
            source,
            parent_encoded.as_slice(),
            parent_manifest.as_slice(),
            subscription.source(),
            intent_encoded.as_slice(),
            intent_manifest.as_slice(),
        ],
        false,
        STAGE_UNSUBSCRIBED_PUBLISH,
        cx,
    )?;
    let retained = RetainedUnsubscribe {
        identity,
        root,
        record,
        subscription,
        source: retained_source,
        anchor,
    };
    cx.checkpoint_post_commit("onvif_control:unsubscribed_committed");
    Ok(retained)
}

fn validate_source(record: &Record, source: &[u8]) -> Result<(), MetadataError> {
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    if source.len() != record.source_bytes || ContentDigest::sha256(source) != record.source {
        return Err(MetadataError::Custody);
    }
    require_relates_to(source, &record.binding.message_id)?;
    parse_unsubscribe_response(source)?;
    Ok(())
}

fn manifest(
    identity: ContentDigest,
    record: &Record,
    subscription: &RetainedSubscription,
) -> Result<ObjectManifest, MetadataError> {
    let mut children = vec![
        identity,
        record.source,
        subscription.identity(),
        subscription.publication_root(),
        subscription.source_digest(),
        subscription.intent.identity(),
        subscription.intent.publication_root(),
    ];
    children.sort_unstable();
    children.dedup();
    ObjectManifest::new(slot(identity, false)?.as_str(), children, None)
        .map_err(crate::ReferenceError::from)
        .map_err(Into::into)
}

fn encode(record: &Record) -> Result<Vec<u8>, MetadataError> {
    if record.subscription.algorithm() != DigestAlgorithm::Sha256
        || record.subscription.bytes() == [0; 32]
        || record.source.algorithm() != DigestAlgorithm::Sha256
        || record.source.bytes() == [0; 32]
        || record.source_bytes == 0
        || record.source_bytes > MAX_SOURCE_BYTES
    {
        return Err(MetadataError::InvalidBinding);
    }
    let binding = &record.binding;
    let mut e = CanonicalEncoder::new();
    e.text(UNSUBSCRIBED_DOMAIN);
    e.text(PARSER_GENERATION);
    e.digest(record.subscription);
    e.text(&binding.route.peer().to_string());
    e.text(binding.route.authority());
    e.text(binding.route.target());
    e.u64(binding.route.generation());
    e.digest(binding.route.plaintext_approval());
    e.text(&binding.message_id);
    e.u64(binding.started_ns);
    e.u64(binding.completed_ns);
    e.i128(binding.receive_interval.earliest.0);
    e.i128(binding.receive_interval.latest.0);
    e.bool(binding.client_authenticated);
    e.digest(record.source);
    e.u64(record.source_bytes as u64);
    let bytes = e.finish_checked()?;
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(MetadataError::Limit);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Record, MetadataError> {
    if bytes.len() > MAX_CONTROL_RECORD_BYTES {
        return Err(MetadataError::Limit);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != UNSUBSCRIBED_DOMAIN || d.text()? != PARSER_GENERATION {
        return Err(MetadataError::Custody);
    }
    let subscription = d.digest()?;
    let peer = d
        .text()?
        .parse::<SocketAddr>()
        .map_err(|_| MetadataError::Custody)?;
    let authority = d.text()?.to_owned();
    let target = d.text()?.to_owned();
    let generation = d.u64()?;
    let approval = d.digest()?;
    let route = HttpRoute::event_service(peer, &authority, &target, generation, approval)
        .map_err(|_| MetadataError::Custody)?;
    let message_id = d.text()?.to_owned();
    let started_ns = d.u64()?;
    let completed_ns = d.u64()?;
    let receive_interval = CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?;
    let client_authenticated = d.bool()?;
    let source = d.digest()?;
    let source_bytes = usize::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?;
    d.ensure_finished()?;
    let record = Record {
        subscription,
        binding: UnsubscribeBinding {
            route,
            message_id,
            started_ns,
            completed_ns,
            receive_interval,
            client_authenticated,
        },
        source,
        source_bytes,
    };
    if encode(&record)? != bytes {
        return Err(MetadataError::Custody);
    }
    Ok(record)
}
