#![forbid(unsafe_code)]
//! Complete Create responses survive interpretation failure and interrupted marker publication.
//! A raw outcome is historical custody, never network, polling, cleanup or retry authority.

use std::fmt;

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    DigestAlgorithm, LedgerAnchor,
};
use fss_object::ObjectManifest;

use super::{
    MAX_CONTROL_RECORD_BYTES, PARSER_GENERATION, RetainedCreateIntent, RetainedSubscription,
    admit_write, codec, finish_read, intent_manifest, publish, read_record, retain_created, slot,
    verify_manifest,
};
use crate::onvif::metadata::{self, MAX_SOURCE_BYTES, MetadataError};
use crate::onvif::wire::{
    PullPointSubscription, parse_pull_point_subscription, require_relates_to,
};
use crate::{ReferenceDeployment, ReplayAdmission, ReplayCx};

/// Additive canonical raw Create-response format. Existing successful response bytes are frozen.
pub const CREATE_OUTCOME_DOMAIN: &str = "fss.onvif_pullpoint_create_outcome.v1";
/// Last cancellable admission before complete Create-response publication.
pub const STAGE_CREATE_OUTCOME_PUBLISH: &str = "onvif_control:create_outcome_publish";

/// Complete HTTP observations, separate from successful subscription interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateOutcomeBinding {
    /// Transport-admitted monotonic completion, absent when no completion time is available.
    pub completed_ns: Option<u64>,
    /// Whether client Digest proof was sent; this does not authenticate the camera.
    pub client_authenticated: bool,
    /// Complete final HTTP status, independent of SOAP validity.
    pub http_status: u16,
    /// Whether the response declared application/soap+xml.
    pub soap_content_type: bool,
}

#[derive(Clone)]
struct Record {
    intent: ContentDigest,
    binding: CreateOutcomeBinding,
    source: ContentDigest,
    source_bytes: usize,
}

/// Exact historical response with authenticated local parent/root/source custody.
/// Private bodies remain available only through the current owner's source-read authority.
#[derive(Clone)]
pub struct RetainedCreateOutcome {
    identity: ContentDigest,
    root: ContentDigest,
    record: Record,
    intent: RetainedCreateIntent,
    source: Vec<u8>,
    subscription: Option<PullPointSubscription>,
    receive_interval: CaptureInterval,
    anchor: LedgerAnchor,
}

impl RetainedCreateOutcome {
    /// Verify complete original intent, exact response bytes, manifest, ledger and deletion state.
    /// No repair, network action, successful marker or remote-state claim is implicit.
    pub fn open<G: ReplayAdmission>(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx<G>,
    ) -> Result<Self, MetadataError> {
        let (encoded, root) = read_record(deployment, identity, false, expected_root, cx)?;
        let record = decode(&encoded)?;
        let intent = RetainedCreateIntent::open(deployment, record.intent, None, cx)?;
        let manifest = manifest(identity, &record, &intent)?;
        verify_manifest(deployment, identity, false, &manifest, root, cx)?;
        let source = metadata::read(deployment, record.source, record.source_bytes, cx)?;
        let receive_interval = validate(&intent, &record, &source)?;
        let mut binding = intent.binding().source.clone();
        binding.receive_interval = receive_interval;
        let anchor = metadata::check_publication(
            deployment,
            &slot(identity, false)?,
            &manifest,
            &binding,
            cx,
        )?;
        finish_read(deployment, &slot(identity, false)?, cx)?;
        let subscription = scoped_subscription(&intent, &record, &source);
        Ok(Self {
            identity,
            root,
            record,
            intent,
            source,
            subscription,
            receive_interval,
            anchor,
        })
    }

    /// Immutable raw-response record identity.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact immutable publication root.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Verified original pre-dispatch obligation; no new dispatch permission.
    pub fn intent(&self) -> &RetainedCreateIntent {
        &self.intent
    }
    /// Exact complete private response, including malformed or rejected bodies.
    pub fn source(&self) -> &[u8] {
        &self.source
    }
    /// Original response digest.
    pub const fn source_digest(&self) -> ContentDigest {
        self.record.source
    }
    /// Complete response length, including zero for an empty HTTP body.
    pub const fn source_bytes(&self) -> usize {
        self.record.source_bytes
    }
    /// HTTP and timing observations, independent of current remote state.
    pub fn binding(&self) -> &CreateOutcomeBinding {
        &self.record.binding
    }
    /// Local admission-to-completion interval; an absent completion retains only admission.
    pub const fn receive_interval(&self) -> CaptureInterval {
        self.receive_interval
    }
    /// Original custody anchor, stable across exact storage retry.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Historical usable response only with time, HTTP200 SOAP, correlation and exact route scope.
    /// A returned reference conveys no current network or cleanup authority.
    pub fn scoped_subscription(&self) -> Option<&PullPointSubscription> {
        self.subscription.as_ref()
    }
}

impl fmt::Debug for RetainedCreateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedCreateOutcome")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("intent", &self.intent.identity())
            .field("source_digest", &self.record.source)
            .field("source_bytes", &self.record.source_bytes)
            .field("scoped_response_observed", &self.subscription.is_some())
            .finish_non_exhaustive()
    }
}

/// Publish every admitted complete final HTTP response before interpreting its SOAP or endpoint.
/// Transport loss before a complete response leaves the existing Create intent unresolved.
pub fn retain_create_outcome<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    intent: &RetainedCreateIntent,
    binding: CreateOutcomeBinding,
    source: &[u8],
    cx: &ReplayCx<G>,
) -> Result<RetainedCreateOutcome, MetadataError> {
    admit_write(deployment, cx)?;
    if source.len() > MAX_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    let intent = RetainedCreateIntent::open(
        deployment,
        intent.identity(),
        Some(intent.publication_root()),
        cx,
    )?;
    let record = Record {
        intent: intent.identity(),
        binding,
        source: ContentDigest::sha256(source),
        source_bytes: source.len(),
    };
    let receive_interval = validate(&intent, &record, source)?;
    let encoded = encode(&record)?;
    let identity = ContentDigest::sha256(&encoded);
    let manifest = manifest(identity, &record, &intent)?;
    let intent_bytes = codec::encode_intent(&intent.record)?;
    let parent_manifest = intent_manifest(intent.identity())?.canonical_bytes();
    let mut source_binding = intent.binding().source.clone();
    source_binding.receive_interval = receive_interval;
    let (root, anchor) = publish(
        deployment,
        identity,
        &manifest,
        &source_binding,
        &[&encoded, source, &intent_bytes, &parent_manifest],
        false,
        STAGE_CREATE_OUTCOME_PUBLISH,
        cx,
    )?;
    // Interpretation cannot discard an admitted complete response: its raw closure is
    // durable before any XML, correlation or returned-endpoint classification occurs.
    let subscription = scoped_subscription(&intent, &record, source);
    let retained = RetainedCreateOutcome {
        identity,
        root,
        record,
        intent,
        source: source.to_vec(),
        subscription,
        receive_interval,
        anchor,
    };
    cx.checkpoint_post_commit("onvif_control:create_outcome_committed");
    Ok(retained)
}

/// Explicitly reconstruct the unchanged successful Created marker from verified raw custody.
/// This performs only local publication. It never sends Create, polls, renews or unsubscribes.
/// Missing, deleted, corrupt, uncorrelated or unscoped evidence refuses without repair.
pub fn recover_created<G: ReplayAdmission>(
    deployment: &mut ReferenceDeployment,
    outcome: &RetainedCreateOutcome,
    cx: &ReplayCx<G>,
) -> Result<RetainedSubscription, MetadataError> {
    let outcome = RetainedCreateOutcome::open(
        deployment,
        outcome.identity(),
        Some(outcome.publication_root()),
        cx,
    )?;
    if outcome.scoped_subscription().is_none() {
        return Err(MetadataError::InvalidBinding);
    }
    retain_created(
        deployment,
        outcome.intent(),
        outcome
            .binding()
            .completed_ns
            .ok_or(MetadataError::InvalidBinding)?,
        outcome.binding().client_authenticated,
        outcome.source(),
        cx,
    )
}

fn validate(
    intent: &RetainedCreateIntent,
    record: &Record,
    source: &[u8],
) -> Result<CaptureInterval, MetadataError> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    if source.len() != record.source_bytes || ContentDigest::sha256(source) != record.source {
        return Err(MetadataError::Custody);
    }
    if !(100..=599).contains(&record.binding.http_status) {
        return Err(MetadataError::InvalidBinding);
    }
    intent.binding().receive_interval(
        record
            .binding
            .completed_ns
            .unwrap_or(intent.binding().started_ns),
    )
}

fn scoped_subscription(
    intent: &RetainedCreateIntent,
    record: &Record,
    source: &[u8],
) -> Option<PullPointSubscription> {
    if record.binding.completed_ns.is_some()
        && record.binding.http_status == 200
        && record.binding.soap_content_type
    {
        require_relates_to(source, &intent.binding().message_id)
            .and_then(|()| parse_pull_point_subscription(source))
            .ok()
            .filter(|subscription| {
                intent
                    .binding()
                    .events
                    .event_subscription(subscription.endpoint(), &intent.binding().service_root)
                    .is_ok()
            })
    } else {
        None
    }
}

fn manifest(
    identity: ContentDigest,
    record: &Record,
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

fn encode(record: &Record) -> Result<Vec<u8>, MetadataError> {
    for digest in [record.intent, record.source] {
        if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
            return Err(MetadataError::InvalidBinding);
        }
    }
    if record.source_bytes > MAX_SOURCE_BYTES || !(100..=599).contains(&record.binding.http_status)
    {
        return Err(MetadataError::InvalidBinding);
    }
    let mut e = CanonicalEncoder::new();
    e.text(CREATE_OUTCOME_DOMAIN);
    e.text(PARSER_GENERATION);
    e.digest(record.intent);
    e.bool(record.binding.completed_ns.is_some());
    if let Some(completed) = record.binding.completed_ns {
        e.u64(completed);
    }
    e.bool(record.binding.client_authenticated);
    e.u64(u64::from(record.binding.http_status));
    e.bool(record.binding.soap_content_type);
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
    if d.text()? != CREATE_OUTCOME_DOMAIN || d.text()? != PARSER_GENERATION {
        return Err(MetadataError::Custody);
    }
    let intent = d.digest()?;
    let completed_ns = if d.bool()? { Some(d.u64()?) } else { None };
    let record = Record {
        intent,
        binding: CreateOutcomeBinding {
            completed_ns,
            client_authenticated: d.bool()?,
            http_status: u16::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?,
            soap_content_type: d.bool()?,
        },
        source: d.digest()?,
        source_bytes: usize::try_from(d.u64()?).map_err(|_| MetadataError::Limit)?,
    };
    d.ensure_finished()?;
    if encode(&record)? != bytes {
        return Err(MetadataError::Custody);
    }
    Ok(record)
}
