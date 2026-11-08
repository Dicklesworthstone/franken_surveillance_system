#![forbid(unsafe_code)]
//! Root-last custody of one completed native webhook observation.
//!
//! The original preparation fixes a single immutable publication slot. Exact observation bytes
//! and their one-child manifest become durable before canonical reachability is appended; only
//! then may the caller record the result in the effect journal. A crash in either gap never
//! authorizes another send. Inspection returns a separate read-only type, never the opaque live
//! WebhookEvidence accepted by the recording API.

use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContextAuthority, ContractError, EffectIntent, EffectJournalTransition, EffectState,
    OperationId, Plane, PreparedEffect, PrincipalId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::{ROOT_REACHABILITY_FAMILY, SlotName, root_reachability_object_id};

use super::{WebhookError, WebhookEvidence, WebhookOutcome, wire};
use crate::alert_control::{CAP_ALERT_STATUS, MAX_CONTROL_JOURNAL_BYTES};
use crate::{DurableEffectError, ReferenceDeployment, ReferenceError, ReplayAdmission, ReplayCx};

mod codec;
mod read_only;

pub use read_only::{
    read_retained_webhook_evidence_from_root, read_retained_webhook_evidence_from_root_with_io,
};

/// Dispatch authority for its explicitly approved local wire retention.
pub const CAP_WEBHOOK_RETENTION: &str = "CAP-ALERT-COMMIT-001";
/// Hard bound before decoding or allocating a complete persisted observation.
pub const MAX_WEBHOOK_OBSERVATION_BYTES: usize = 32_768;
/// Hard bound for the canonical single-child manifest.
pub const MAX_WEBHOOK_MANIFEST_BYTES: usize = 512;
/// Conservative payload/publication byte reservation, independent of effect-history reads.
pub const WEBHOOK_CUSTODY_BYTES: u64 = 262_144;
/// Conservative logical storage-operation reservation, independent of history-read admission.
pub const WEBHOOK_CUSTODY_STORAGE_OPERATIONS: u64 = 32;
/// Stable slot identity; terminal reconciliation cannot replace the original wire observation.
pub const WEBHOOK_RETENTION_SLOT_DOMAIN: &str = "fss.http-webhook-retention-slot.v1";
/// Bounded allowance for the framed Committed transition appended after a successful preflight.
const COMMIT_HISTORY_HEADROOM_BYTES: u64 = 4096;

const STAGE_AUTHORITY: &str = "webhook_custody:authority";
const STAGE_HISTORY: &str = "webhook_custody:history";
const STAGE_ROOT: &str = "webhook_custody:root";
const STAGE_MANIFEST: &str = "webhook_custody:manifest";
const STAGE_OBSERVATION: &str = "webhook_custody:observation";
const STAGE_STAGE: &str = "webhook_custody:stage";
const STAGE_PUBLISH: &str = "webhook_custody:publish";
const STAGE_RETAINED: &str = "webhook_custody:retained";

/// Fail-closed local custody failures. None of these permits retransmission.
#[derive(Debug)]
pub enum WebhookRetentionError {
    /// Explicit principal, capability, deployment or live admission does not match.
    Unauthorized,
    /// The bounded custody or history reservation exceeds its budget.
    Budget,
    /// Live owner admission refused this boundary.
    Cancelled,
    /// The operation is absent or is not an alert dispatch.
    NotAlert,
    /// Canonical bytes, preparation or committed history disagree.
    Invalid,
    /// Another observation or a retracted publication already owns this slot.
    Conflict,
    /// Current physical custody or canonical authority linkage is unavailable.
    Custody,
    /// Shared canonical contract refused the input.
    Contract(ContractError),
    /// The publication owner refused or did not finish the root-last commit.
    Deployment(ReferenceError),
    /// The durable effect history could not be verified.
    Journal(DurableEffectError),
    /// A live observation is not finalized or cannot be encoded.
    Observation(WebhookError),
}

impl WebhookRetentionError {
    /// Stable existing error family, without response bytes or filesystem details.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::NotAlert | Self::Invalid | Self::Conflict | Self::Custody => {
                "ERR-ALERT-AUTHORITY-001"
            }
            _ => "ERR-ALERT-DISPATCH-001",
        }
    }
}

impl fmt::Display for WebhookRetentionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unauthorized => "webhook custody authority denied",
            Self::Budget => "webhook custody budget exceeded",
            Self::Cancelled => "webhook custody live owner refused admission",
            Self::NotAlert => "no retained alert dispatch has this operation identity",
            Self::Invalid | Self::Contract(_) => {
                "webhook observation or committed binding is invalid"
            }
            Self::Conflict => "webhook observation conflicts with the existing retention slot",
            Self::Custody => "webhook observation lacks current verified durable custody",
            Self::Deployment(_) => "webhook publication is unresolved; inspect without resending",
            Self::Journal(_) => "webhook committed history could not be verified",
            Self::Observation(_) => "webhook observation is not finalized or cannot be encoded",
        })
    }
}
impl std::error::Error for WebhookRetentionError {}
impl From<ContractError> for WebhookRetentionError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<ReferenceError> for WebhookRetentionError {
    fn from(value: ReferenceError) -> Self {
        Self::Deployment(value)
    }
}
impl From<DurableEffectError> for WebhookRetentionError {
    fn from(value: DurableEffectError) -> Self {
        Self::Journal(value)
    }
}

/// Verified read-only local observation. This is never provider delivery proof or live evidence
/// usable by record_webhook_evidence. Debug and default reports omit arbitrary wire bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct RetainedWebhookEvidence {
    observation: codec::Observation,
    digest: ContentDigest,
    root: ContentDigest,
    slot: SlotName,
    prepared: ContentDigest,
    journal_observation_recorded: bool,
}

impl fmt::Debug for RetainedWebhookEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedWebhookEvidence")
            .field("operation", &self.intent().operation_id)
            .field("digest", &self.digest)
            .field("root", &self.root)
            .field("slot", &self.slot)
            .field("outcome", &self.outcome())
            .field(
                "journal_observation_recorded",
                &self.journal_observation_recorded,
            )
            .field("request_bytes", &self.request().len())
            .field("sent_bytes", &self.sent_bytes())
            .field("response_prefix_bytes", &self.response_prefix().len())
            .finish_non_exhaustive()
    }
}

impl RetainedWebhookEvidence {
    /// Digest of the exact existing observation-v1 bytes.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Canonical one-child manifest root.
    #[must_use]
    pub const fn root(&self) -> ContentDigest {
        self.root
    }
    /// Canonical one-child manifest root.
    #[must_use]
    pub const fn manifest_root(&self) -> ContentDigest {
        self.root
    }
    /// Immutable slot bound to site, operation and original preparation.
    #[must_use]
    pub const fn slot(&self) -> &SlotName {
        &self.slot
    }
    /// Exact original effect intent.
    #[must_use]
    pub const fn intent(&self) -> &EffectIntent {
        &self.observation.intent
    }
    /// Original prepared record, independent of any later terminal proof.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> ContentDigest {
        self.prepared
    }
    /// Exact effect-journal root at which the adapter observed commitment.
    #[must_use]
    pub const fn commitment_root(&self) -> ContentDigest {
        self.observation.commitment_root
    }
    /// Frozen route digest, without disclosing its address.
    #[must_use]
    pub const fn route_digest(&self) -> ContentDigest {
        self.observation.route
    }
    /// Complete bounded request; disclose only through an explicitly authorized surface.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.observation.request
    }
    /// Request prefix actually accepted by local socket writes.
    #[must_use]
    pub const fn sent_bytes(&self) -> usize {
        self.observation.sent
    }
    /// Exact bounded response prefix, including untrusted bytes; never format by default.
    #[must_use]
    pub fn response_prefix(&self) -> &[u8] {
        &self.observation.response
    }
    /// Socket operation attempts consumed by this observation.
    #[must_use]
    pub const fn io_calls(&self) -> u64 {
        self.observation.calls
    }
    /// Recorded local transport outcome; acceptance is not human delivery.
    #[must_use]
    pub const fn outcome(&self) -> WebhookOutcome {
        self.observation.outcome
    }
    /// Independently admitted original commit time.
    #[must_use]
    pub const fn committed_ns(&self) -> u64 {
        self.observation.committed_ns
    }
    /// Original network deadline, never extended during retention.
    #[must_use]
    pub const fn deadline_ns(&self) -> u64 {
        self.observation.deadline_ns
    }
    /// Last caller or owner sample retained by the live adapter.
    #[must_use]
    pub const fn last_admission_ns(&self) -> u64 {
        self.observation.last_admission_ns
    }
    /// Whether a matching local observation transition exists in verified historical records.
    /// False for publication before journal recording; terminal reconciliation preserves an
    /// earlier exact match. This flag is not provider authentication.
    #[must_use]
    pub const fn journal_observation_recorded(&self) -> bool {
        self.journal_observation_recorded
    }
}

fn checkpoint(
    cx: &ReplayCx<impl ReplayAdmission>,
    stage: &'static str,
) -> Result<(), WebhookRetentionError> {
    cx.checkpoint(stage)
        .map_err(|_| WebhookRetentionError::Cancelled)
}

/// Effect-history read reservation for preflight, retention and local result recording.
///
/// One full read occurs in preflight, at most two in retention, and one in result recording.
/// Every read is bounded to the
/// exact opened committed length plus one growth-probe byte. A conservative 4 KiB allowance
/// covers the intervening framed Committed transition. Reserve this separately from the
/// exported custody byte envelope; it is never an unlimited or zero-budget fallback.
pub fn webhook_retention_history_bytes(
    deployment: &ReferenceDeployment,
) -> Result<u64, WebhookRetentionError> {
    let maximum = deployment
        .effects()
        .committed_len()
        .checked_add(COMMIT_HISTORY_HEADROOM_BYTES)
        .ok_or(WebhookRetentionError::Budget)?;
    if maximum > MAX_CONTROL_JOURNAL_BYTES {
        return Err(WebhookRetentionError::Budget);
    }
    maximum
        .checked_add(1)
        .and_then(|one| one.checked_mul(4))
        .ok_or(WebhookRetentionError::Budget)
}

fn authorize(
    deployment: &ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx<impl ReplayAdmission>,
    capability: &str,
) -> Result<(), WebhookRetentionError> {
    authority.validate()?;
    checkpoint(cx, STAGE_AUTHORITY)?;
    if !authority.has_capability(capability)
        || authority.cancellation_reason.is_some()
        || (authority.deadline.is_some() && !cx.has_owner_admission())
        || cx.root_dir() != deployment.root()
        || cx.io_authority().principal() != authority.principal
        || authority.anchor_universe != ContentDigest::sha256(deployment.site_lineage().as_bytes())
        || PrincipalId::parse(&authority.principal).is_err()
    {
        return Err(WebhookRetentionError::Unauthorized);
    }
    let length = deployment.effects().committed_len();
    let bytes = length
        .checked_add(1)
        .and_then(|one| one.checked_mul(2))
        .and_then(|history| history.checked_add(WEBHOOK_CUSTODY_BYTES))
        .ok_or(WebhookRetentionError::Budget)?;
    if length > MAX_CONTROL_JOURNAL_BYTES
        || authority.budgets.bytes < bytes
        || authority.budgets.storage_operations < WEBHOOK_CUSTODY_STORAGE_OPERATIONS
    {
        return Err(WebhookRetentionError::Budget);
    }
    if !deployment.ledger().store_pin_is_current() {
        return Err(WebhookRetentionError::Unauthorized);
    }
    checkpoint(cx, STAGE_AUTHORITY)?;
    if !deployment.effects().store_pin_is_current() {
        return Err(WebhookRetentionError::Unauthorized);
    }
    checkpoint(cx, STAGE_HISTORY)?;
    // This existing check reads at most the final 40-byte commit trailer, not the whole ledger.
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| WebhookRetentionError::Custody)?;
    checkpoint(cx, STAGE_HISTORY)
}

fn prepared(
    deployment: &ReferenceDeployment,
    operation_id: &OperationId,
) -> Result<PreparedEffect, WebhookRetentionError> {
    let receipt = deployment
        .effects()
        .operation(operation_id)
        .ok_or(WebhookRetentionError::NotAlert)?;
    if receipt.intent.effect_class != "alert.dispatch" {
        return Err(WebhookRetentionError::NotAlert);
    }
    let prepared = deployment
        .effects()
        .effect_journal()
        .prepared_record(operation_id)?;
    if prepared.intent != receipt.intent {
        return Err(WebhookRetentionError::Invalid);
    }
    Ok(prepared)
}

fn slot(site: &str, prepared: &PreparedEffect) -> Result<SlotName, WebhookRetentionError> {
    let mut e = CanonicalEncoder::new();
    e.text(WEBHOOK_RETENTION_SLOT_DOMAIN);
    e.text(site);
    e.text(prepared.intent.operation_id.as_str());
    e.digest(prepared.prepared_record_digest());
    let digest = ContentDigest::sha256(&e.finish_checked()?);
    SlotName::parse(&format!("alert-wire-{}", wire::hex(digest)))
        .map_err(|_| WebhookRetentionError::Invalid)
}

fn verify_commitment(
    deployment: &ReferenceDeployment,
    prepared: &PreparedEffect,
    observation: &codec::Observation,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<bool, WebhookRetentionError> {
    if observation.intent != prepared.intent {
        return Err(WebhookRetentionError::Invalid);
    }
    checkpoint(cx, STAGE_HISTORY)?;
    let report = deployment
        .effects()
        .verified_history_bounded(MAX_CONTROL_JOURNAL_BYTES as usize)?;
    checkpoint(cx, STAGE_HISTORY)?;
    verify_history_binding(report.records(), prepared, observation)
}

fn verify_history_binding(
    records: &[fss_ledger::JournalRecord],
    prepared: &PreparedEffect,
    observation: &codec::Observation,
) -> Result<bool, WebhookRetentionError> {
    let position = records
        .iter()
        .position(|record| record.root() == observation.commitment_root)
        .ok_or(WebhookRetentionError::Invalid)?;
    let history = crate::durable_effect::replay_records(&records[..=position])?;
    let committed = history
        .operation(&prepared.intent.operation_id)
        .ok_or(WebhookRetentionError::Invalid)?;
    if committed.state != EffectState::Committed
        || committed.intent != prepared.intent
        || committed.committed_at != Some(TimestampNs(i128::from(observation.committed_ns)))
        || history
            .prepared_record(&prepared.intent.operation_id)?
            .prepared_record_digest()
            != prepared.prepared_record_digest()
    {
        return Err(WebhookRetentionError::Invalid);
    }
    let digest = observation.digest();
    let expected = match observation.outcome {
        WebhookOutcome::ReceiverAccepted(_) => EffectState::AdapterAccepted,
        _ => EffectState::Indeterminate,
    };
    for record in &records[position + 1..] {
        if let EffectJournalTransition::Transition {
            operation_id,
            next,
            now,
            result_digest,
            ..
        } = EffectJournalTransition::from_canonical_bytes(record.payload())?
        {
            if operation_id == prepared.intent.operation_id
                && next == expected
                && result_digest == Some(digest)
                && now >= TimestampNs(i128::from(observation.last_admission_ns))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn current_claim(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
) -> Result<Option<ContentDigest>, WebhookRetentionError> {
    let object = root_reachability_object_id(slot).map_err(|_| WebhookRetentionError::Invalid)?;
    let Some(revision) = deployment.ledger().current().objects.get(&object) else {
        return Ok(None);
    };
    if revision.family != ROOT_REACHABILITY_FAMILY
        || revision.plane != Plane::Authority
        || revision.generation != 1
    {
        return Err(WebhookRetentionError::Conflict);
    }
    Ok(Some(revision.payload_digest))
}

fn read_custody(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    root: ContentDigest,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<(ObjectManifest, Vec<u8>), WebhookRetentionError> {
    checkpoint(cx, STAGE_ROOT)?;
    let visible = deployment
        .publisher()
        .root(slot)
        .ok_or(WebhookRetentionError::Custody)?;
    if visible.root != root || visible.child_count != 1 {
        return Err(WebhookRetentionError::Custody);
    }
    deployment
        .publisher()
        .require_durable_record(slot)
        .map_err(|_| WebhookRetentionError::Custody)?;
    checkpoint(cx, STAGE_MANIFEST)?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(root, MAX_WEBHOOK_MANIFEST_BYTES)
        .map_err(|_| WebhookRetentionError::Custody)?;
    checkpoint(cx, STAGE_MANIFEST)?;
    let manifest =
        ObjectManifest::from_canonical_bytes(&bytes).map_err(|_| WebhookRetentionError::Invalid)?;
    if manifest.root() != root
        || manifest.kind() != slot.as_str()
        || manifest.children().len() != 1
        || manifest.metadata_digest().is_some()
        || manifest.canonical_bytes() != bytes
    {
        return Err(WebhookRetentionError::Invalid);
    }
    let digest = manifest.children()[0];
    checkpoint(cx, STAGE_OBSERVATION)?;
    let observation = deployment
        .publisher()
        .spool()
        .read_bounded(digest, MAX_WEBHOOK_OBSERVATION_BYTES)
        .map_err(|_| WebhookRetentionError::Custody)?;
    checkpoint(cx, STAGE_OBSERVATION)?;
    Ok((manifest, observation))
}

fn verify_linkage(
    deployment: &ReferenceDeployment,
    slot: &SlotName,
    manifest: &ObjectManifest,
) -> Result<(), WebhookRetentionError> {
    let object = root_reachability_object_id(slot).map_err(|_| WebhookRetentionError::Invalid)?;
    let batch_id = fss_publication::root_reachability_batch_id(slot)
        .map_err(|_| WebhookRetentionError::Invalid)?;
    if !deployment.ledger().batches().iter().any(|batch| {
        batch.batch_id == batch_id
            && batch.children == manifest.children()
            && batch.deltas.len() == 1
            && batch.deltas.iter().any(|delta| {
                delta.object_id == object
                    && delta.family == ROOT_REACHABILITY_FAMILY
                    && delta.payload_digest == manifest.root()
                    && delta.plane == Plane::Authority
                    && delta.prior_generation.is_none()
                    && delta.new_generation == 1
                    && delta.witness_digest.is_none()
                    && delta.operation_id.is_none()
            })
    }) {
        return Err(WebhookRetentionError::Custody);
    }
    Ok(())
}

fn inspect(
    deployment: &ReferenceDeployment,
    prepared: &PreparedEffect,
    slot: &SlotName,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<Option<RetainedWebhookEvidence>, WebhookRetentionError> {
    let Some(root) = current_claim(deployment, slot)? else {
        if deployment.publisher().root(slot).is_some()
            || deployment.publisher().is_broken_slot(slot)
        {
            return Err(WebhookRetentionError::Custody);
        }
        checkpoint(cx, STAGE_HISTORY)?;
        deployment
            .effects()
            .verified_history_bounded(MAX_CONTROL_JOURNAL_BYTES as usize)?;
        checkpoint(cx, STAGE_HISTORY)?;
        return Ok(None);
    };
    let (manifest, bytes) = read_custody(deployment, slot, root, cx)?;
    verify_linkage(deployment, slot, &manifest)?;
    let observation = codec::decode(&bytes)?;
    let journal_observation_recorded = verify_commitment(deployment, prepared, &observation, cx)?;
    checkpoint(cx, STAGE_RETAINED)?;
    Ok(Some(RetainedWebhookEvidence {
        digest: manifest.children()[0],
        root,
        slot: slot.clone(),
        prepared: prepared.prepared_record_digest(),
        observation,
        journal_observation_recorded,
    }))
}

/// Read verified local wire custody without modifying either journal or publication.
/// This never opens a socket, changes effect state, or creates recording authority.
pub fn read_retained_webhook_evidence(
    deployment: &ReferenceDeployment,
    operation_id: &OperationId,
    authority: &ContextAuthority,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<Option<RetainedWebhookEvidence>, WebhookRetentionError> {
    authorize(deployment, authority, cx, CAP_ALERT_STATUS)?;
    let prepared = prepared(deployment, operation_id)?;
    let slot = slot(deployment.site_lineage(), &prepared)?;
    inspect(deployment, &prepared, &slot, cx)
}

/// Validate retention authority and its reserved envelope before committing a network effect.
///
/// Checks an unsent preparation against current store pins and verified history without
/// creating a slot or changing either journal. Reserve webhook_retention_history_bytes plus
/// WEBHOOK_CUSTODY_BYTES before calling. Later retention still needs the original owner's
/// current clock, cancellation and explicit local cleanup grant; preflight cannot freeze them.
pub fn check_webhook_retention(
    deployment: &ReferenceDeployment,
    operation_id: &OperationId,
    authority: &ContextAuthority,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<(), WebhookRetentionError> {
    authorize(deployment, authority, cx, CAP_WEBHOOK_RETENTION)?;
    let required = webhook_retention_history_bytes(deployment)?
        .checked_add(WEBHOOK_CUSTODY_BYTES)
        .ok_or(WebhookRetentionError::Budget)?;
    if authority.budgets.bytes < required {
        return Err(WebhookRetentionError::Budget);
    }
    let prepared = prepared(deployment, operation_id)?;
    let current = deployment
        .effects()
        .operation(operation_id)
        .ok_or(WebhookRetentionError::NotAlert)?;
    if current.state != EffectState::Prepared
        || current.committed_at.is_some()
        || current.result_digest.is_some()
    {
        return Err(WebhookRetentionError::Conflict);
    }
    let slot = slot(deployment.site_lineage(), &prepared)?;
    if current_claim(deployment, &slot)?.is_some()
        || deployment.publisher().root(&slot).is_some()
        || deployment.publisher().is_broken_slot(&slot)
    {
        return Err(WebhookRetentionError::Conflict);
    }
    // Refuse known configured exhaustion before any network effect. This is a conservative
    // two-object/one-root reservation, not a promise about later operating-system failures.
    let publisher = deployment.publisher();
    let spool = publisher.spool();
    let limits = spool.limits();
    let objects = spool
        .object_count()
        .checked_add(2)
        .ok_or(WebhookRetentionError::Budget)?;
    let occupied = spool
        .occupied_bytes()
        .map_err(|_| WebhookRetentionError::Budget)?
        .checked_add(MAX_WEBHOOK_OBSERVATION_BYTES as u64)
        .and_then(|bytes| bytes.checked_add(MAX_WEBHOOK_MANIFEST_BYTES as u64))
        .ok_or(WebhookRetentionError::Budget)?;
    if limits.max_object_bytes < MAX_WEBHOOK_OBSERVATION_BYTES
        || objects > limits.max_objects
        || occupied > limits.max_total_bytes
        || publisher.visible_roots().count() >= publisher.limits().max_roots
    {
        return Err(WebhookRetentionError::Budget);
    }
    checkpoint(cx, STAGE_HISTORY)?;
    deployment
        .effects()
        .verified_history_bounded(MAX_CONTROL_JOURNAL_BYTES as usize)?;
    checkpoint(cx, STAGE_HISTORY)
}

/// Persist a genuine completed observation before its effect-journal result transition.
///
/// The owner reserves custody bytes/storage plus the separate bounded history-read envelope
/// before network commitment. Finite deadlines require with_admission with the original owner.
/// Exact retries re-read custody without appending; different observations cannot reuse the
/// slot. Failure leaves the effect journal untouched and never permits another network attempt.
pub fn retain_webhook_evidence(
    deployment: &mut ReferenceDeployment,
    evidence: &WebhookEvidence,
    authority: &ContextAuthority,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<RetainedWebhookEvidence, WebhookRetentionError> {
    authorize(deployment, authority, cx, CAP_WEBHOOK_RETENTION)?;
    let prepared = prepared(deployment, &evidence.intent().operation_id)?;
    let slot = slot(deployment.site_lineage(), &prepared)?;
    let bytes = evidence
        .encoded()
        .map_err(WebhookRetentionError::Observation)?;
    let observation = codec::decode(&bytes)?;
    let digest = ContentDigest::sha256(&bytes);
    let manifest =
        ObjectManifest::new(slot.as_str(), vec![digest], None).map_err(ReferenceError::from)?;
    if manifest.canonical_bytes().len() > MAX_WEBHOOK_MANIFEST_BYTES {
        return Err(WebhookRetentionError::Budget);
    }
    verify_commitment(deployment, &prepared, &observation, cx)?;
    if let Some(root) = current_claim(deployment, &slot)? {
        if root != manifest.root() {
            return Err(WebhookRetentionError::Conflict);
        }
        return inspect(deployment, &prepared, &slot, cx)?.ok_or(WebhookRetentionError::Custody);
    }
    let current = deployment
        .effects()
        .operation(&prepared.intent.operation_id)
        .ok_or(WebhookRetentionError::NotAlert)?;
    if !matches!(
        current.state,
        EffectState::Committed | EffectState::Indeterminate
    ) || current.result_digest.is_some()
    {
        return Err(WebhookRetentionError::Conflict);
    }
    if deployment.publisher().is_broken_slot(&slot) {
        return Err(WebhookRetentionError::Custody);
    }
    if let Some(visible) = deployment.publisher().root(&slot) {
        if visible.root != manifest.root() {
            return Err(WebhookRetentionError::Conflict);
        }
        let (stored, stored_bytes) = read_custody(deployment, &slot, visible.root, cx)?;
        if stored != manifest || stored_bytes != bytes {
            return Err(WebhookRetentionError::Conflict);
        }
    } else {
        checkpoint(cx, STAGE_STAGE)?;
        let staged = deployment.stage_and_publish(&slot, &[&bytes], cx)?;
        if staged.manifest != manifest {
            return Err(WebhookRetentionError::Invalid);
        }
        checkpoint(cx, STAGE_STAGE)?;
    }
    checkpoint(cx, STAGE_PUBLISH)?;
    deployment.publish_and_commit(
        &slot,
        &manifest,
        CaptureInterval::new(
            TimestampNs(i128::from(observation.committed_ns)),
            TimestampNs(i128::from(observation.last_admission_ns)),
        )?,
        cx,
    )?;
    // The root owner drains an already-started publication commit. A refusal afterward must
    // not let the caller record a result without current verified custody.
    checkpoint(cx, STAGE_RETAINED)?;
    inspect(deployment, &prepared, &slot, cx)?.ok_or(WebhookRetentionError::Custody)
}
