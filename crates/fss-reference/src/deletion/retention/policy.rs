#![forbid(unsafe_code)]
//! Immutable per-sensor retention settings with exact adoption and cleanup approvals.
//!
//! Policy adoption changes future configuration, never deletes evidence. A cleanup pins one
//! current enabled generation and still needs its own exact deletion-plan approval. No clock,
//! daemon, automatic hold release or standing authority over future imports is inferred.

use std::collections::BTreeMap;
use std::fmt;

use fss_core::region::ContextAuthority;
use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, DigestAlgorithm, EvidenceDelta, LedgerAnchor, ObjectId, Plane,
    PrincipalId, SensorId, TimestampNs,
};

use super::{RetentionPlan, RetentionRequest, plan_retention};
use crate::deletion::holds::{CAP_HOLD_COMMIT, CAP_HOLD_PREPARE};
use crate::deletion::{
    DeletionError, DeletionIndex, DeletionPlan, DeletionScope, MAX_DELETION_RECORD_BYTES,
};
use crate::reference_deployment::FAMILY_RETENTION_POLICY;
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Canonical immutable authority record.
pub const POLICY_DOMAIN: &str = "fss.retention_policy.v1";
/// Stable per-site and per-sensor authority object identity, independent of generation.
pub const POLICY_ID_DOMAIN: &str = "fss.retention_policy_id.v1";
/// Exact approval of the policy record, its predecessor, basis and affected selection.
pub const POLICY_APPROVAL_DOMAIN: &str = "fss.retention_policy_approval.v1";
/// Reserved authority namespace; a generic family cannot shadow an adopted policy.
pub const POLICY_OBJECT_PREFIX: &str = "object:retention-policy:";
/// Maximum sensors with policy history, including disabled policies.
pub const MAX_POLICIES: usize = 256;
/// Maximum lifetime policy revisions; history is never evicted to make room.
pub const MAX_POLICY_RECORDS: usize = 1024;
/// Maximum bytes per canonical record, enforced before allocating its payload.
pub const MAX_POLICY_RECORD_BYTES: u64 = 8192;
/// Shared payload allowance across a complete policy-history pass.
pub const MAX_POLICY_READ_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum ledger batches and deltas examined in a complete history pass.
pub const MAX_POLICY_LEDGER_ENTRIES: u64 = 1_000_000;
/// Cooperative metadata-read checkpoint.
pub const STAGE_POLICY_READ: &str = "retention_policy:read";
/// Last checkpoint before staging a fully revalidated policy revision.
pub const STAGE_POLICY_REVALIDATED: &str = "retention_policy:revalidated";
/// A retained impact preview is audit metadata, not an adopted policy or deletion authority.
pub const STAGE_POLICY_IMPACT_STAGED: &str = "retention_policy:impact_staged";
/// A staged record grants no authority until its ledger batch commits.
pub const STAGE_POLICY_STAGED: &str = "retention_policy:staged";
/// Post-commit cancellation point, never reported as failure of an already committed change.
pub const STAGE_POLICY_COMMITTED: &str = "retention_policy:committed";

/// Complete prospective change. All settings are explicit, including disabling a policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyChangeRequest {
    /// Exact sensor; this implementation covers completed local file imports only.
    pub sensor: SensorId,
    /// Whether fresh cleanup requests may use this generation.
    pub enabled: bool,
    /// Positive minimum age. A byte target never weakens this floor.
    pub retain_for_ns: u64,
    /// Optional distinct completed same-sensor full-input byte target; zero is allowed.
    pub max_retained_source_bytes: Option<u64>,
    /// Exact current record to replace, or no prior policy for first adoption.
    pub expected_policy: Option<ContentDigest>,
    /// Owner assertion used only to preview the affected current inventory.
    pub attested_now: CaptureInterval,
    /// Bounded operator rationale; no media or secret content.
    pub reason: String,
}

impl PolicyChangeRequest {
    /// Refuse malformed requests before any deployment read.
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.inline_request()?;
        if self
            .expected_policy
            .is_some_and(|digest| digest.algorithm() != DigestAlgorithm::Sha256)
            || self.reason.trim().is_empty()
            || self.reason.len() > 512
            || self.reason.chars().any(char::is_control)
        {
            return Err(PolicyError::InvalidRequest);
        }
        Ok(())
    }

    fn inline_request(&self) -> Result<RetentionRequest, PolicyError> {
        let request =
            RetentionRequest::new(self.sensor.clone(), self.retain_for_ns, self.attested_now)
                .map_err(|_| PolicyError::InvalidRequest)?;
        Ok(match self.max_retained_source_bytes {
            Some(bytes) => request.with_source_byte_budget(bytes),
            None => request,
        })
    }
}

/// One verified, immutable policy generation in canonical authority history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionPolicyRecord {
    request: PolicyChangeRequest,
    generation: u64,
    principal: String,
    site: String,
    basis: LedgerAnchor,
    affected_selection: ContentDigest,
    affected_plan: Option<ContentDigest>,
}

impl RetentionPolicyRecord {
    /// Complete exact adoption request, including its predecessor pin.
    #[must_use]
    pub fn request(&self) -> &PolicyChangeRequest {
        &self.request
    }
    /// Monotone authority generation; disabled generations are retained too.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Local audit principal, not remote authentication.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
    /// Exact authority lineage.
    #[must_use]
    pub fn site(&self) -> &str {
        &self.site
    }
    /// Authority head against which this revision and its impact were approved.
    #[must_use]
    pub fn basis(&self) -> &LedgerAnchor {
        &self.basis
    }
    /// Immutable age/byte selection inspected before adopting these settings.
    #[must_use]
    pub const fn affected_selection(&self) -> ContentDigest {
        self.affected_selection
    }
    /// Proposed affected-object plan, if any; adoption did not authorize or execute it.
    #[must_use]
    pub const fn affected_plan(&self) -> Option<ContentDigest> {
        self.affected_plan
    }

    /// Canonical authority payload. Capture assertions are separate from the ledger basis.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text(POLICY_DOMAIN);
        self.request.sensor.encode_canonical(&mut e);
        e.bool(self.request.enabled);
        e.u64(self.request.retain_for_ns);
        e.bool(self.request.max_retained_source_bytes.is_some());
        if let Some(bytes) = self.request.max_retained_source_bytes {
            e.u64(bytes);
        }
        e.bool(self.request.expected_policy.is_some());
        if let Some(digest) = self.request.expected_policy {
            e.digest(digest);
        }
        self.request.attested_now.earliest.encode_canonical(&mut e);
        self.request.attested_now.latest.encode_canonical(&mut e);
        e.text(&self.request.reason);
        e.u64(self.generation);
        e.text(&self.principal);
        e.text(&self.site);
        self.basis.encode_canonical(&mut e);
        e.digest(self.affected_selection);
        e.bool(self.affected_plan.is_some());
        if let Some(digest) = self.affected_plan {
            e.digest(digest);
        }
        e.finish()
    }
    /// Exact immutable record identity.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }
    /// Owner approval of this complete prospective mutation; never deletion authority.
    #[must_use]
    pub fn approval(&self) -> ContentDigest {
        let mut e = CanonicalEncoder::new();
        e.text(POLICY_APPROVAL_DOMAIN);
        e.digest(self.digest());
        ContentDigest::sha256(&e.finish())
    }
    /// Strict canonical decoding against independently retained ledger identity.
    pub fn from_bytes(bytes: &[u8], expected: ContentDigest) -> Result<Self, PolicyError> {
        if bytes.len() as u64 > MAX_POLICY_RECORD_BYTES || ContentDigest::sha256(bytes) != expected
        {
            return Err(PolicyError::InvalidRecord);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != POLICY_DOMAIN {
            return Err(PolicyError::InvalidRecord);
        }
        let sensor = SensorId::decode_canonical(&mut d)?;
        let enabled = d.bool()?;
        let retain_for_ns = d.u64()?;
        let max_retained_source_bytes = if d.bool()? { Some(d.u64()?) } else { None };
        let expected_policy = if d.bool()? { Some(d.digest()?) } else { None };
        let attested_now = CaptureInterval::new(
            TimestampNs::decode_canonical(&mut d)?,
            TimestampNs::decode_canonical(&mut d)?,
        )?;
        let reason = d.text()?.to_owned();
        let generation = d.u64()?;
        let principal = d.text()?.to_owned();
        let site = d.text()?.to_owned();
        let basis = LedgerAnchor::decode_canonical(&mut d)?;
        let affected_selection = d.digest()?;
        let affected_plan = if d.bool()? { Some(d.digest()?) } else { None };
        d.ensure_finished()?;
        let record = Self {
            request: PolicyChangeRequest {
                sensor,
                enabled,
                retain_for_ns,
                max_retained_source_bytes,
                expected_policy,
                attested_now,
                reason,
            },
            generation,
            principal,
            site,
            basis,
            affected_selection,
            affected_plan,
        };
        record
            .request
            .validate()
            .map_err(|_| PolicyError::InvalidRecord)?;
        PrincipalId::parse(&record.principal).map_err(|_| PolicyError::InvalidRecord)?;
        crate::reference_deployment::validate_site_lineage(&record.site)
            .map_err(|_| PolicyError::InvalidRecord)?;
        if record.principal.len() > 256
            || record.site.len() > 256
            || generation == 0
            || (generation == 1) != expected_policy.is_none()
            || record.basis.site_lineage != record.site
            || affected_selection.algorithm() != DigestAlgorithm::Sha256
            || affected_plan.is_some_and(|digest| digest.algorithm() != DigestAlgorithm::Sha256)
            || record.to_bytes() != bytes
        {
            return Err(PolicyError::InvalidRecord);
        }
        Ok(record)
    }
    fn object_id(&self) -> Result<ObjectId, PolicyError> {
        let mut e = CanonicalEncoder::new();
        e.text(POLICY_ID_DOMAIN);
        e.text(&self.site);
        self.request.sensor.encode_canonical(&mut e);
        Ok(ObjectId::parse(format!(
            "{POLICY_OBJECT_PREFIX}{}",
            hex(ContentDigest::sha256(&e.finish()))
        ))?)
    }
    fn batch_id(&self) -> Result<BatchId, PolicyError> {
        Ok(BatchId::parse(format!(
            "batch:retention-policy:{}",
            hex(self.digest())
        ))?)
    }
    fn children(&self) -> Vec<ContentDigest> {
        let mut children = vec![self.digest()];
        children.extend(self.request.expected_policy);
        children.extend(self.affected_plan);
        children.sort_unstable();
        children.dedup();
        children
    }
    fn delta(&self) -> Result<EvidenceDelta, PolicyError> {
        Ok(EvidenceDelta {
            delta_id: format!("delta:retention-policy:{}", hex(self.digest())),
            family: FAMILY_RETENTION_POLICY.to_owned(),
            object_id: self.object_id()?,
            prior_generation: self
                .generation
                .checked_sub(1)
                .filter(|generation| *generation != 0),
            new_generation: self.generation,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
            plane: Plane::Authority,
            payload_digest: self.digest(),
            witness_digest: self.request.expected_policy,
            operation_id: None,
        })
    }
}

/// Typed refusal; missing or damaged policy custody never becomes an absent policy.
#[derive(Debug)]
pub enum PolicyError {
    /// Invalid request, scope or bounded rationale.
    InvalidRequest,
    /// Missing or mismatched runtime authority.
    Unauthorized,
    /// Requested record does not exist in verified policy history.
    UnknownPolicy,
    /// Expected predecessor or current pinned generation changed.
    StalePolicy,
    /// Current policy explicitly disables fresh cleanup under that generation.
    Disabled,
    /// Approval does not match the exact affected-object and policy revision preview.
    StaleApproval,
    /// Authority changes cannot race a deletion already recorded but not complete.
    DeletionInProgress,
    /// History, bytes, ledger work or canonical representation exceeded its hard bound.
    Limit,
    /// Authority record, chain, namespace or custody is inconsistent.
    InvalidRecord,
    /// Cooperative cancellation before commit.
    Cancelled,
    /// Underlying canonical failure.
    Contract(ContractError),
    /// Underlying deployment failure.
    Reference(Box<ReferenceError>),
    /// Underlying custody failure.
    Spool(fss_object::SpoolError),
    /// Affected deletion selection or history refused.
    Deletion(Box<DeletionError>),
}
impl PolicyError {
    /// Stable machine refusal; details never contain source bytes.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        match self {
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::InvalidRequest | Self::UnknownPolicy => "ERR-RETENTION-POLICY-REQUEST-001",
            Self::StalePolicy | Self::Disabled => "ERR-RETENTION-POLICY-STALE-001",
            Self::StaleApproval => "ERR-RETENTION-POLICY-APPROVAL-001",
            Self::DeletionInProgress => "ERR-RETENTION-POLICY-DELETION-IN-PROGRESS-001",
            Self::Limit => "ERR-RETENTION-POLICY-BOUND-001",
            Self::Cancelled => "ERR-RETENTION-POLICY-CANCELLED-001",
            Self::Deletion(error) => error.stable_id(),
            _ => "ERR-RETENTION-POLICY-STORAGE-001",
        }
    }
}
impl fmt::Display for PolicyError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => out.write_str("invalid retention policy request"),
            Self::Unauthorized => out.write_str("retention policy authority denied or mismatched"),
            Self::UnknownPolicy => {
                out.write_str("retention policy record is not in retained authority history")
            }
            Self::StalePolicy => {
                out.write_str("retention policy generation changed; inspect and prepare again")
            }
            Self::Disabled => out.write_str("retention policy generation is disabled"),
            Self::StaleApproval => {
                out.write_str("retention policy approval is stale; preview the exact change again")
            }
            Self::DeletionInProgress => out.write_str(
                "a deletion has started but is incomplete; finish it before changing policy",
            ),
            Self::Limit => out.write_str("retention policy history or work bound exhausted"),
            Self::InvalidRecord => {
                out.write_str("retention policy authority or custody is inconsistent")
            }
            Self::Cancelled => out.write_str("retention policy operation cancelled before commit"),
            Self::Contract(error) => write!(out, "retention policy contract: {error}"),
            Self::Reference(error) => write!(out, "retention policy authority: {error}"),
            Self::Spool(error) => write!(out, "retention policy custody: {error}"),
            Self::Deletion(error) => write!(out, "retention policy impact: {error}"),
        }
    }
}
impl std::error::Error for PolicyError {}
impl From<ContractError> for PolicyError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<ReferenceError> for PolicyError {
    fn from(error: ReferenceError) -> Self {
        Self::Reference(Box::new(error))
    }
}
impl From<fss_object::SpoolError> for PolicyError {
    fn from(error: fss_object::SpoolError) -> Self {
        Self::Spool(error)
    }
}
impl From<DeletionError> for PolicyError {
    fn from(error: DeletionError) -> Self {
        Self::Deletion(Box::new(error))
    }
}

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), PolicyError> {
    cx.checkpoint(stage).map_err(|_| PolicyError::Cancelled)
}
fn authorize(
    deployment: &ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    capability: &str,
) -> Result<(), PolicyError> {
    authority.validate()?;
    checkpoint(cx, STAGE_POLICY_READ)?;
    if cx.root_dir() != deployment.root()
        || authority.principal != cx.io_authority().principal()
        || !authority.has_capability(capability)
        || authority.cancellation_reason.is_some()
        || authority.anchor_universe != ContentDigest::sha256(deployment.site_lineage().as_bytes())
        || authority.principal.len() > 256
        || deployment.site_lineage().len() > 256
    {
        return Err(PolicyError::Unauthorized);
    }
    Ok(())
}

#[derive(Default)]
struct PolicyIndex {
    current: BTreeMap<SensorId, ContentDigest>,
    records: BTreeMap<ContentDigest, RetentionPolicyRecord>,
    bytes_read: u64,
}
impl PolicyIndex {
    fn read(deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<Self, PolicyError> {
        checkpoint(cx, STAGE_POLICY_READ)?;
        if cx.root_dir() != deployment.root() {
            return Err(PolicyError::Unauthorized);
        }
        let mut index = Self::default();
        let mut entries = 0_u64;
        let mut bytes_read = 0_u64;
        for batch in deployment.ledger().batches() {
            checkpoint(cx, STAGE_POLICY_READ)?;
            entries = entries
                .checked_add(1 + batch.deltas.len() as u64)
                .ok_or(PolicyError::Limit)?;
            if entries > MAX_POLICY_LEDGER_ENTRIES {
                return Err(PolicyError::Limit);
            }
            for delta in &batch.deltas {
                if delta.family != FAMILY_RETENTION_POLICY
                    && !delta.object_id.as_str().starts_with(POLICY_OBJECT_PREFIX)
                {
                    continue;
                }
                if index.records.len() == MAX_POLICY_RECORDS {
                    return Err(PolicyError::Limit);
                }
                checkpoint(cx, STAGE_POLICY_READ)?;
                let remaining = MAX_POLICY_READ_BYTES
                    .checked_sub(bytes_read)
                    .ok_or(PolicyError::Limit)?;
                let bytes = deployment
                    .publisher()
                    .spool()
                    .read_bounded(delta.payload_digest, MAX_POLICY_RECORD_BYTES.min(remaining))?;
                bytes_read = bytes_read
                    .checked_add(bytes.len() as u64)
                    .ok_or(PolicyError::Limit)?;
                let record = RetentionPolicyRecord::from_bytes(&bytes, delta.payload_digest)?;
                if record.site != deployment.site_lineage()
                    || record.basis != batch.basis_anchor
                    || batch.deltas.len() != 1
                    || *delta != record.delta()?
                    || batch.batch_id != record.batch_id()?
                    || batch.children != record.children()
                    || index.records.contains_key(&delta.payload_digest)
                {
                    return Err(PolicyError::InvalidRecord);
                }
                if let Some(digest) = record.affected_plan {
                    checkpoint(cx, STAGE_POLICY_READ)?;
                    let remaining = MAX_POLICY_READ_BYTES
                        .checked_sub(bytes_read)
                        .ok_or(PolicyError::Limit)?;
                    let bytes = deployment
                        .publisher()
                        .spool()
                        .read_bounded(digest, (MAX_DELETION_RECORD_BYTES as u64).min(remaining))?;
                    bytes_read = bytes_read
                        .checked_add(bytes.len() as u64)
                        .ok_or(PolicyError::Limit)?;
                    let plan = DeletionPlan::decode(&bytes, digest)?;
                    if plan.site_lineage != record.site
                        || plan.basis_anchor != record.basis
                        || !matches!(&plan.scope, DeletionScope::Retention(selection)
                            if selection.request() == &record.request.inline_request()?
                                && selection.digest()? == record.affected_selection)
                    {
                        return Err(PolicyError::InvalidRecord);
                    }
                }
                let prior = index.current.get(&record.request.sensor).copied();
                if prior != record.request.expected_policy {
                    return Err(PolicyError::InvalidRecord);
                }
                let expected_generation = match prior {
                    Some(digest) => index
                        .records
                        .get(&digest)
                        .ok_or(PolicyError::InvalidRecord)?
                        .generation
                        .checked_add(1)
                        .ok_or(PolicyError::Limit)?,
                    None => {
                        if index.current.len() == MAX_POLICIES {
                            return Err(PolicyError::Limit);
                        }
                        1
                    }
                };
                if record.generation != expected_generation {
                    return Err(PolicyError::InvalidRecord);
                }
                index
                    .current
                    .insert(record.request.sensor.clone(), record.digest());
                index.records.insert(record.digest(), record);
            }
        }
        for digest in index.current.values() {
            checkpoint(cx, STAGE_POLICY_READ)?;
            let record = index
                .records
                .get(digest)
                .ok_or(PolicyError::InvalidRecord)?;
            let object_id = record.object_id()?;
            let current = deployment
                .ledger()
                .current()
                .objects
                .get(&object_id)
                .ok_or(PolicyError::InvalidRecord)?;
            if current.family != FAMILY_RETENTION_POLICY
                || current.plane != Plane::Authority
                || current.generation != record.generation
                || current.payload_digest != *digest
            {
                return Err(PolicyError::InvalidRecord);
            }
        }
        index.bytes_read = bytes_read;
        Ok(index)
    }
}

/// Preparation or exact retry outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyOutcome {
    /// Read-only proposal requiring approval.
    Proposed,
    /// The policy revision is now authoritative; no media was deleted.
    Committed,
    /// Exact request already committed as the current revision; no writes.
    AlreadyCurrent,
}
impl PolicyOutcome {
    /// Stable machine spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Committed => "committed",
            Self::AlreadyCurrent => "already_current",
        }
    }
}
/// Policy change and its read-only impact. A retry retains the original impact identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyReceipt {
    /// Exact immutable mutation record.
    pub record: RetentionPolicyRecord,
    /// Whether this call proposes or committed a revision.
    pub outcome: PolicyOutcome,
    /// Present for a fresh preview/commit; absent for an already committed exact retry.
    /// Its deletion approval is separate and becomes stale when this policy is committed.
    pub affected: Option<RetentionPlan>,
}

/// Current policies, including disabled ones, in sensor order; no history is mutated.
pub fn list_policies(
    deployment: &ReferenceDeployment,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<Vec<RetentionPolicyRecord>, PolicyError> {
    authorize(deployment, authority, cx, CAP_HOLD_PREPARE)?;
    let index = PolicyIndex::read(deployment, cx)?;
    index
        .current
        .values()
        .map(|digest| {
            index
                .records
                .get(digest)
                .cloned()
                .ok_or(PolicyError::InvalidRecord)
        })
        .collect()
}

/// Prepare settings against the exact current generation, authority and affected-object plan.
pub fn preview_policy_change(
    deployment: &ReferenceDeployment,
    request: &PolicyChangeRequest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<PolicyReceipt, PolicyError> {
    request.validate()?;
    authorize(deployment, authority, cx, CAP_HOLD_PREPARE)?;
    let index = PolicyIndex::read(deployment, cx)?;
    let current = index.current.get(&request.sensor).copied();
    if let Some(digest) = current {
        let record = index
            .records
            .get(&digest)
            .ok_or(PolicyError::InvalidRecord)?;
        if record.request == *request && record.principal == authority.principal {
            return Ok(PolicyReceipt {
                record: record.clone(),
                outcome: PolicyOutcome::AlreadyCurrent,
                affected: None,
            });
        }
    }
    if current != request.expected_policy {
        return Err(PolicyError::StalePolicy);
    }
    if index.records.len() == MAX_POLICY_RECORDS
        || (current.is_none() && index.current.len() == MAX_POLICIES)
    {
        return Err(PolicyError::Limit);
    }
    if DeletionIndex::read(deployment)?
        .entries()
        .iter()
        .any(|entry| !entry.is_complete())
    {
        return Err(PolicyError::DeletionInProgress);
    }
    let generation = match current {
        Some(digest) => index
            .records
            .get(&digest)
            .ok_or(PolicyError::InvalidRecord)?
            .generation
            .checked_add(1)
            .ok_or(PolicyError::Limit)?,
        None => 1,
    };
    let affected = plan_retention(deployment, &request.inline_request()?, cx)?;
    let record = RetentionPolicyRecord {
        request: request.clone(),
        generation,
        principal: authority.principal.clone(),
        site: deployment.site_lineage().to_owned(),
        basis: deployment.current_anchor().clone(),
        affected_selection: affected.assessment.selection.digest()?,
        affected_plan: affected
            .deletion
            .as_ref()
            .map(|plan| plan.digest())
            .transpose()?,
    };
    if record.to_bytes().len() as u64 > MAX_POLICY_RECORD_BYTES {
        return Err(PolicyError::Limit);
    }
    let additional = record.to_bytes().len() as u64
        + affected
            .deletion
            .as_ref()
            .map(|plan| plan.canonical_bytes())
            .transpose()?
            .map_or(0, |bytes| bytes.len() as u64);
    if index
        .bytes_read
        .checked_add(additional)
        .is_none_or(|bytes| bytes > MAX_POLICY_READ_BYTES)
    {
        return Err(PolicyError::Limit);
    }
    Ok(PolicyReceipt {
        record,
        outcome: PolicyOutcome::Proposed,
        affected: Some(affected),
    })
}

/// Commit the exact prospective change; never delete bytes or grant later deletion approval.
pub fn commit_policy_change(
    deployment: &mut ReferenceDeployment,
    request: &PolicyChangeRequest,
    approval: ContentDigest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<PolicyReceipt, PolicyError> {
    authorize(deployment, authority, cx, CAP_HOLD_COMMIT)?;
    let mut receipt = preview_policy_change(deployment, request, authority, cx)?;
    if receipt.record.approval() != approval {
        return Err(PolicyError::StaleApproval);
    }
    if receipt.outcome == PolicyOutcome::AlreadyCurrent {
        return Ok(receipt);
    }
    checkpoint(cx, STAGE_POLICY_REVALIDATED)?;
    if let Some(plan) = receipt
        .affected
        .as_ref()
        .and_then(|affected| affected.deletion.as_ref())
    {
        let digest = deployment.stage_payload(&plan.canonical_bytes()?)?;
        if Some(digest) != receipt.record.affected_plan {
            return Err(PolicyError::InvalidRecord);
        }
        checkpoint(cx, STAGE_POLICY_IMPACT_STAGED)?;
    }
    let digest = deployment.stage_payload(&receipt.record.to_bytes())?;
    if digest != receipt.record.digest() {
        return Err(PolicyError::InvalidRecord);
    }
    checkpoint(cx, STAGE_POLICY_STAGED)?;
    deployment.append_retention_policy_batch(
        receipt.record.batch_id()?,
        vec![receipt.record.delta()?],
        receipt.record.children(),
        cx,
    )?;
    receipt.outcome = PolicyOutcome::Committed;
    cx.checkpoint_post_commit(STAGE_POLICY_COMMITTED);
    Ok(receipt)
}

/// Policy approval records, including staged pre-commit records, are audit metadata rather
/// than source/derivative keys. The walker treats them like retained deletion-plan records.
pub(crate) fn is_policy_record_bytes(
    bytes: &[u8],
    digest: ContentDigest,
) -> Result<bool, PolicyError> {
    if !CanonicalDecoder::new(bytes)
        .text()
        .is_ok_and(|domain| domain == POLICY_DOMAIN)
    {
        return Ok(false);
    }
    // A marker alone is not an exemption from graph scanning. The exact canonical bounded
    // authority-record grammar must verify, even for a cancelled pre-commit staged record.
    RetentionPolicyRecord::from_bytes(bytes, digest)?;
    Ok(true)
}

/// Resolve a retained policy generation into its exact cleanup request. Historical and disabled
/// records may be resolved for durable retries; fresh planning separately requires current+enabled.
/// Caller supplies deletion read/commit authority as for the existing retention entry points.
pub fn request_from_policy(
    deployment: &ReferenceDeployment,
    policy: ContentDigest,
    attested_now: CaptureInterval,
    cx: &ReplayCx,
) -> Result<RetentionRequest, PolicyError> {
    CaptureInterval::new(attested_now.earliest, attested_now.latest)?;
    let index = PolicyIndex::read(deployment, cx)?;
    let record = index
        .records
        .get(&policy)
        .ok_or(PolicyError::UnknownPolicy)?;
    let mut request = record.request.inline_request()?;
    request.now_earliest_ns = attested_now.earliest.0;
    request.now_latest_ns = attested_now.latest.0;
    request.policy = Some(policy);
    Ok(request)
}

/// Current generation and complete inherited settings must agree before any fresh selection.
pub(super) fn validate_current_request(
    deployment: &ReferenceDeployment,
    request: &RetentionRequest,
    cx: &ReplayCx,
) -> Result<(), PolicyError> {
    let pin = request.policy.ok_or(PolicyError::InvalidRequest)?;
    let index = PolicyIndex::read(deployment, cx)?;
    let record = index.records.get(&pin).ok_or(PolicyError::UnknownPolicy)?;
    if index.current.get(&request.sensor) != Some(&pin) {
        return Err(PolicyError::StalePolicy);
    }
    if !record.request.enabled {
        return Err(PolicyError::Disabled);
    }
    if record.request.sensor != request.sensor
        || record.request.retain_for_ns != request.retain_for_ns
        || record.request.max_retained_source_bytes != request.source_byte_budget
    {
        return Err(PolicyError::InvalidRecord);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn record() -> Result<RetentionPolicyRecord, PolicyError> {
        Ok(RetentionPolicyRecord {
            request: PolicyChangeRequest {
                sensor: SensorId::parse("sensor:policy-test")?,
                enabled: true,
                retain_for_ns: 100,
                max_retained_source_bytes: Some(0),
                expected_policy: None,
                attested_now: CaptureInterval::new(TimestampNs(1000), TimestampNs(1010))?,
                reason: "Owner-reviewed cleanup".to_owned(),
            },
            generation: 1,
            principal: "principal:test".to_owned(),
            site: "site:policy-test".to_owned(),
            basis: LedgerAnchor::genesis("site:policy-test"),
            affected_selection: ContentDigest::sha256(b"affected selection"),
            affected_plan: None,
        })
    }

    #[test]
    fn policy_codec_binds_exact_settings_and_rejects_forged_initial_generation() -> TestResult {
        let original = record()?;
        assert_eq!(
            RetentionPolicyRecord::from_bytes(&original.to_bytes(), original.digest())?,
            original
        );
        for mutation in 0..6 {
            let mut forged = original.clone();
            match mutation {
                0 => forged.generation = 0,
                1 => forged.generation = 2,
                2 => forged.request.expected_policy = Some(ContentDigest::sha256(b"prior")),
                3 => forged.request.retain_for_ns = 0,
                4 => forged.request.reason = "\n".to_owned(),
                _ => forged.basis.site_lineage = "site:foreign".to_owned(),
            }
            assert!(
                RetentionPolicyRecord::from_bytes(&forged.to_bytes(), forged.digest()).is_err(),
                "mutation {mutation}"
            );
        }
        let mut changed = original.clone();
        changed.request.max_retained_source_bytes = None;
        assert_ne!(changed.digest(), original.digest());
        assert_ne!(changed.approval(), original.approval());
        assert!(RetentionPolicyRecord::from_bytes(&changed.to_bytes(), original.digest()).is_err());
        let mut trailing = original.to_bytes();
        trailing.push(0);
        assert!(
            RetentionPolicyRecord::from_bytes(&trailing, ContentDigest::sha256(&trailing)).is_err()
        );
        Ok(())
    }

    #[test]
    fn policy_audit_marker_requires_complete_canonical_record_not_an_arbitrary_prefix() -> TestResult
    {
        let good = record()?;
        assert!(is_policy_record_bytes(&good.to_bytes(), good.digest())?);
        let unrelated = b"a normal retained media object";
        assert!(!is_policy_record_bytes(
            unrelated,
            ContentDigest::sha256(unrelated)
        )?);
        let mut marker = CanonicalEncoder::new();
        marker.text(POLICY_DOMAIN);
        let marker = marker.finish();
        assert!(is_policy_record_bytes(&marker, ContentDigest::sha256(&marker)).is_err());
        let mut oversized = good.to_bytes();
        oversized.resize(MAX_POLICY_RECORD_BYTES as usize + 1, 0);
        assert!(is_policy_record_bytes(&oversized, ContentDigest::sha256(&oversized)).is_err());
        Ok(())
    }
}
