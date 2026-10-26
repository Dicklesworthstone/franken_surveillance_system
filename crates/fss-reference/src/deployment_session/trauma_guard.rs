#![forbid(unsafe_code)]
//! Experiential operational memory and trauma-guard anti-pattern warning derivation
//! (`GOAL-018`, `NS-13`, `NEG-004`, `GATE-090`).
//!
//! **Advisory only (`NEG-004`).** When a deployment accumulates repeated (`>= 2`) negative
//! operational memory signals (`AgentFeedbackProposal` records of kind `harmful`,
//! `hard_negative_candidate`, `bad_affordance`, or `adapter_quirk`, or terminal `Failed`
//! `ExecutionEpisode` records) on the same target and failure/attribution cause class, this module
//! deterministically derives an advisory [`AntiPatternWarning`] citing the exact episode/feedback
//! identities, evidence digests, and exponential half-life decay weight (`TRAUMA_HALF_LIFE_NS`).
//!
//! Deriving or surfacing an [`AntiPatternWarning`] never mutates policy, thresholds, retention,
//! calibration, models, or authority (`AntiPatternWarning::ACTIVE_POLICY_MUTATION == false`).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};

use fss_core::{
    AttributionCauseClass, CanonicalEncoder, ContentDigest, ContractError, EpisodeOutcomeState,
    FeedbackPrivacyClass, FeedbackProposalKind, PrincipalId,
};

use super::episode::{EpisodeRecord, TerminalOutcome};
use super::feedback::{FeedbackTarget, decode_proposal, target_json};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::plan::PlanRecord;
use super::{
    DeploymentSessionError, MAX_RECORD_BYTES, PUBLICATIONS_RELPATH, PublishedRecord, digest_of,
    hex, publication_limits,
};

/// Digest domain (`SCHEMA-DOMAIN-AGENT-TRAUMA-GUARD-001`).
pub const TRAUMA_GUARD_DOMAIN: &str = "fss.reference_agent_trauma_guard.v1";

/// Minimum number of negative operational memory records on the same `(target, cause_class)` tuple
/// required to trigger an advisory [`AntiPatternWarning`].
pub const TRAUMA_GUARD_MIN_NEGATIVE_COUNT: usize = 2;

/// Default exponential decay half-life in nanoseconds (24 hours).
pub const TRAUMA_HALF_LIFE_NS: i128 = 86_400_000_000_000;

/// Full decay weight for a zero-age negative record in parts-per-million (`1.0 == 1_000_000`).
pub const MAX_RECORD_WEIGHT_PPM: u64 = 1_000_000;

/// Maximum feedback and episode records decoded in one advisory-memory scan, across owners.
pub const MAX_TRAUMA_SOURCE_RECORDS: usize = 256;
/// Maximum bytes materialized after the structurally bounded publication inspection.
/// This is not a meter of the inspection's filesystem reads or metadata operations.
pub const MAX_TRAUMA_MATERIALIZED_BYTES: usize = 16 * 1024 * 1024;
/// Maximum recurring anti-patterns admitted into one canonical orientation.
pub const MAX_TRAUMA_WARNINGS: usize = 64;
/// Maximum distinct supporting publication and evidence roots retained by one warning.
pub const MAX_TRAUMA_EVIDENCE_DIGESTS: usize = 1024;
/// Maximum portable warning summary; oversized history refuses instead of being truncated.
pub const MAX_TRAUMA_SUMMARY_BYTES: usize = 16 * 1024;

/// One deterministically derived advisory trauma-guard warning (`NS-13` / `GOAL-018`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntiPatternWarning {
    /// Deterministic warning identity (`trauma-guard:<32-hex>`).
    pub warning_id: String,
    /// Canonical target JSON (`{"id":...,"kind":...}`).
    pub target_json: String,
    /// Attribution / failure cause class of the recurring anti-pattern.
    pub cause_class: AttributionCauseClass,
    /// Count of negative episode/feedback records contributing to this warning.
    pub negative_count: usize,
    /// Half-life window in nanoseconds used for decay weighting.
    pub half_life_ns: i128,
    /// Summed half-life decay weight in parts-per-million across all cited negative records.
    pub decay_weight_ppm: u64,
    /// Sorted, deduplicated `episode:...` / `feedback:...` identities cited by this warning.
    pub cited_record_ids: Vec<String>,
    /// Sorted, deduplicated publication root and supporting evidence digests.
    pub cited_evidence_digests: Vec<ContentDigest>,
    /// Compile-time invariant (`NEG-004`): always `false`.
    pub active_policy_mutation: bool,
}

impl AntiPatternWarning {
    /// Compile-time `NEG-004` invariant: trauma-guard warnings never mutate active policy.
    pub const ACTIVE_POLICY_MUTATION: bool = false;

    /// Validates an admitted advisory before it becomes protected canonical context.
    ///
    /// A warning asserts that harmful historical reports exist. It never establishes their
    /// truth about the current target or grants permission to change policy or execute effects.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.active_policy_mutation {
            return Err(ContractError::DerivedLayerAuthorityForbidden);
        }
        if self.negative_count < TRAUMA_GUARD_MIN_NEGATIVE_COUNT
            || self.negative_count != self.cited_record_ids.len()
            || self.half_life_ns != TRAUMA_HALF_LIFE_NS
            || self.decay_weight_ppm < self.negative_count as u64
            || self.decay_weight_ppm
                > (self.negative_count as u64).saturating_mul(MAX_RECORD_WEIGHT_PPM)
        {
            return Err(ContractError::DigestMismatch);
        }
        if self.negative_count > MAX_TRAUMA_SOURCE_RECORDS
            || self.cited_evidence_digests.len() > MAX_TRAUMA_EVIDENCE_DIGESTS
            || self.target_json.len() > 4096
        {
            return Err(ContractError::CountBoundExceeded);
        }
        if self.cited_evidence_digests.is_empty() {
            return Err(ContractError::EvidenceRequired);
        }
        if self.target_json.is_empty()
            || self.cited_record_ids.iter().any(|id| {
                id.len() > 256
                    || !(id.starts_with("feedback:") || id.starts_with("episode:"))
                    || id.bytes().any(|byte| byte.is_ascii_control())
            })
        {
            return Err(ContractError::InvalidIdentifier);
        }
        if self
            .cited_record_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
            || self
                .cited_evidence_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ContractError::NonCanonicalOrdering);
        }
        if self.warning_id
            != warning_identity(&self.target_json, self.cause_class, &self.cited_record_ids)
        {
            return Err(ContractError::DigestMismatch);
        }
        if self.summary().len() > MAX_TRAUMA_SUMMARY_BYTES {
            return Err(ContractError::CountBoundExceeded);
        }
        Ok(())
    }

    /// Canonical content digest of this warning under [`TRAUMA_GUARD_DOMAIN`].
    #[must_use]
    pub fn canonical_digest(&self) -> ContentDigest {
        digest_of(TRAUMA_GUARD_DOMAIN, |encoder: &mut CanonicalEncoder| {
            encoder.text(&self.warning_id);
            encoder.text(&self.target_json);
            encoder.text(self.cause_class.as_str());
            encoder.u64(self.negative_count as u64);
            encoder.i128(self.half_life_ns);
            encoder.u64(self.decay_weight_ppm);
            encoder.u32(self.cited_record_ids.len() as u32);
            for id in &self.cited_record_ids {
                encoder.text(id);
            }
            encoder.u32(self.cited_evidence_digests.len() as u32);
            for digest in &self.cited_evidence_digests {
                encoder.digest(*digest);
            }
            encoder.bool(self.active_policy_mutation);
        })
    }

    /// Canonical single-line advisory warning surfaced in `SituationCapsule` / `orient` responses.
    #[must_use]
    pub fn summary(&self) -> String {
        let cites = self.cited_record_ids.join(",");
        let digests = self
            .cited_evidence_digests
            .iter()
            .map(|d| d.to_text())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "trauma_guard_warning[{}]: target={} cause={} negative_count={} decay_weight_ppm={} half_life_ns={} active_policy_mutation={} cites=[{}] digests=[{}]",
            self.warning_id,
            self.target_json,
            self.cause_class.as_str(),
            self.negative_count,
            self.decay_weight_ppm,
            self.half_life_ns,
            self.active_policy_mutation,
            cites,
            digests,
        )
    }
}

/// Computes deterministic integer exponential half-life decay weight in parts-per-million (`[1, 1_000_000]`).
///
/// Uses exact integer division `epochs = age_ns / half_life_ns` and linear fractional interpolation
/// between `2^-epochs` and `2^-(epochs + 1)` so no floating-point nondeterminism can ever occur.
#[must_use]
pub fn compute_decay_weight_ppm(
    reference_time_ns: i128,
    record_time_ns: i128,
    half_life_ns: i128,
) -> u64 {
    if half_life_ns <= 0 {
        return MAX_RECORD_WEIGHT_PPM;
    }
    let age_ns = reference_time_ns.saturating_sub(record_time_ns).max(0);
    let epochs = (age_ns / half_life_ns).min(20) as u32;
    let rem_ns = (age_ns % half_life_ns) as u128;
    let hl = half_life_ns as u128;
    let base = u128::from(MAX_RECORD_WEIGHT_PPM) >> epochs;
    let next = base >> 1;
    let drop = ((base - next) * rem_ns) / hl;
    (base.saturating_sub(drop) as u64).max(1)
}

fn negative_feedback_cause(kind: FeedbackProposalKind) -> Option<AttributionCauseClass> {
    match kind {
        FeedbackProposalKind::HardNegativeCandidate => Some(AttributionCauseClass::Hypothesis),
        FeedbackProposalKind::Harmful => Some(AttributionCauseClass::Execution),
        FeedbackProposalKind::BadAffordance => Some(AttributionCauseClass::ContextSelection),
        FeedbackProposalKind::AdapterQuirk => Some(AttributionCauseClass::Adapter),
        _ => None,
    }
}

#[derive(Default)]
struct Bucket {
    cause_class: Option<AttributionCauseClass>,
    record_ids: BTreeSet<String>,
    digests: BTreeSet<ContentDigest>,
    decay_weight_ppm: u64,
}

fn warning_identity(target: &str, cause: AttributionCauseClass, record_ids: &[String]) -> String {
    let digest = digest_of(TRAUMA_GUARD_DOMAIN, |encoder| {
        encoder.text(target);
        encoder.text(cause.as_str());
        encoder.u32(record_ids.len() as u32);
        for id in record_ids {
            encoder.text(id);
        }
    });
    format!(
        "trauma-guard:{}",
        hex(digest).chars().take(32).collect::<String>()
    )
}

fn invalid_memory(reason: &str) -> DeploymentSessionError {
    // Do not disclose another owner's record identity or private target in refusal text.
    DeploymentSessionError::StoreInvalid(format!("advisory operational memory: {reason}"))
}

fn memory_slot(kind: &str, identity: &str) -> Result<SlotName, DeploymentSessionError> {
    SlotName::parse(&format!(
        "{kind}-{}",
        hex(ContentDigest::sha256(identity.as_bytes()))
    ))
    .map_err(|_| invalid_memory("invalid publication identity"))
}

struct MemoryReader {
    directory: PathBuf,
    remaining_bytes: usize,
}

impl MemoryReader {
    fn object(&mut self, digest: ContentDigest) -> Result<Vec<u8>, DeploymentSessionError> {
        if self.remaining_bytes == 0 {
            return Err(invalid_memory("materialized-byte bound exhausted"));
        }
        let bytes = fss_publication::read_verified(
            &self.directory,
            digest,
            self.remaining_bytes.min(MAX_RECORD_BYTES),
        )
        .map_err(|_| {
            invalid_memory("source object failed verification or exceeded its read bound")
        })?;
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(bytes.len())
            .ok_or_else(|| invalid_memory("materialized-byte bound exhausted"))?;
        Ok(bytes)
    }

    fn record(&mut self, root: ContentDigest) -> Result<PublishedRecord, DeploymentSessionError> {
        let bytes = self.object(root)?;
        let manifest = ObjectManifest::from_canonical_bytes(&bytes)
            .map_err(|_| invalid_memory("source manifest is not canonical"))?;
        if manifest.root() != root {
            return Err(invalid_memory("source manifest root differs"));
        }
        let metadata = manifest
            .metadata_digest()
            .ok_or_else(|| invalid_memory("source metadata is absent"))?;
        let record = self.object(metadata)?;
        let children: Vec<_> = manifest
            .children()
            .iter()
            .copied()
            .filter(|child| *child != metadata)
            .collect();
        Ok(PublishedRecord {
            root,
            record,
            children,
        })
    }

    fn verify_children(
        &mut self,
        published: &PublishedRecord,
    ) -> Result<(), DeploymentSessionError> {
        // Re-read only after owner admission. Inspection checks closure; these reads guard
        // against a retained child changing since that inspection without expanding others'
        // private report renderings unnecessarily.
        for child in &published.children {
            self.object(*child)?;
        }
        Ok(())
    }
}

fn add_record(
    bucket: &mut Bucket,
    id: String,
    record_time_ns: i128,
    reference_time_ns: i128,
    roots: impl IntoIterator<Item = ContentDigest>,
) -> Result<(), DeploymentSessionError> {
    if !bucket.record_ids.insert(id) {
        return Err(invalid_memory("duplicate retained record identity"));
    }
    bucket.decay_weight_ppm = bucket
        .decay_weight_ppm
        .checked_add(compute_decay_weight_ppm(
            reference_time_ns,
            record_time_ns.max(0),
            TRAUMA_HALF_LIFE_NS,
        ))
        .ok_or_else(|| invalid_memory("decay weight overflow"))?;
    bucket.digests.extend(roots);
    if bucket.record_ids.len() > MAX_TRAUMA_SOURCE_RECORDS
        || bucket.digests.len() > MAX_TRAUMA_EVIDENCE_DIGESTS
    {
        return Err(invalid_memory("warning source bound exceeded"));
    }
    Ok(())
}

/// Derives advisory warnings only from the named principal's retained operational history.
///
/// The caller must first admit situation-read and private-property visibility. Historical
/// sessions and missions owned by this principal may contribute; this does not establish
/// applicability to a current mission. Other owners are excluded before grouping or plan lookup.
/// Publication inspection uses the deployment's existing structural bounds; materialized
/// records and warning output have the additional explicit bounds above. A missing publication
/// directory is observed empty. Unreadable, malformed, incomplete, or over-budget history is
/// refused in full, never silently treated as no harmful history.
pub fn derive_trauma_guard_warnings(
    root: &Path,
    principal: &PrincipalId,
    reference_time_ns: i128,
) -> Result<Vec<AntiPatternWarning>, DeploymentSessionError> {
    let directory = root.join(PUBLICATIONS_RELPATH);
    match std::fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(invalid_memory("publication directory is not a directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(invalid_memory("publication directory is unreadable")),
    }
    let inspection = fss_publication::inspect(&directory, publication_limits())
        .map_err(|_| invalid_memory("publication inspection failed"))?;
    let is_memory = |slot: &SlotName| {
        slot.as_str().starts_with("feedback-") || slot.as_str().starts_with("episode-")
    };
    // Broken roots are not included in visible_roots. Check them separately before returning
    // an empty result; corruption must never turn a warning into apparent absence.
    if inspection.broken_slots().any(is_memory) {
        return Err(invalid_memory(
            "a retained memory publication is incomplete or corrupt",
        ));
    }
    let sources: Vec<_> = inspection
        .visible_roots()
        .filter(|root| is_memory(&root.slot))
        .collect();
    if sources.len() > MAX_TRAUMA_SOURCE_RECORDS {
        return Err(invalid_memory("retained source-record bound exceeded"));
    }
    let mut reader = MemoryReader {
        directory,
        remaining_bytes: MAX_TRAUMA_MATERIALIZED_BYTES,
    };
    let mut buckets: BTreeMap<(String, &'static str), Bucket> = BTreeMap::new();
    let mut plans: BTreeMap<String, (PlanRecord, ContentDigest, ContentDigest)> = BTreeMap::new();

    for source in sources {
        let published = reader.record(source.root)?;
        if source.slot.as_str().starts_with("feedback-") {
            let proposal = decode_proposal(&published.record)
                .map_err(|_| invalid_memory("a feedback record is not canonical"))?;
            if source.slot != memory_slot("feedback", &proposal.feedback_id)? {
                return Err(invalid_memory(
                    "feedback identity differs from its publication",
                ));
            }
            if proposal.principal_id != *principal {
                continue;
            }
            let Some(cause) = negative_feedback_cause(proposal.kind) else {
                continue;
            };
            if matches!(
                proposal.privacy_class,
                FeedbackPrivacyClass::Restricted | FeedbackPrivacyClass::SecretReferenceOnly
            ) {
                return Err(invalid_memory("feedback requires a stronger privacy scope"));
            }
            reader.verify_children(&published)?;
            let mut roots = vec![published.root];
            for handle in &proposal.supporting_evidence {
                roots.push(
                    ContentDigest::parse(handle)
                        .map_err(|_| invalid_memory("feedback evidence handle is invalid"))?,
                );
            }
            let bucket = buckets
                .entry((proposal.target_json, cause.as_str()))
                .or_default();
            bucket.cause_class = Some(cause);
            add_record(
                bucket,
                proposal.feedback_id,
                proposal.created_at_ns,
                reference_time_ns,
                roots,
            )?;
        } else {
            let record = EpisodeRecord::from_bytes(&published.record)
                .map_err(|_| invalid_memory("an episode record is not canonical"))?;
            if source.slot != memory_slot("episode", &record.episode.episode_id)? {
                return Err(invalid_memory(
                    "episode identity differs from its publication",
                ));
            }
            if record.principal != *principal {
                continue;
            }
            if record.terminal_state != TerminalOutcome::Failed
                && record.episode.outcome.state != EpisodeOutcomeState::Failed
            {
                continue;
            }
            reader.verify_children(&published)?;
            if !plans.contains_key(&record.plan_id) {
                let slot = memory_slot("plan", &record.plan_id)?;
                if inspection.is_broken_slot(&slot) {
                    return Err(invalid_memory("a failed episode's plan is corrupt"));
                }
                let visible = inspection
                    .root(&slot)
                    .ok_or_else(|| invalid_memory("a failed episode's plan is missing"))?;
                let published_plan = reader.record(visible.root)?;
                let plan = PlanRecord::from_bytes(&published_plan.record)
                    .map_err(|_| invalid_memory("a failed episode's plan is not canonical"))?;
                if plan.plan_id != record.plan_id
                    || plan.principal != *principal
                    || published_plan.children != vec![plan.control_plan_digest]
                {
                    return Err(invalid_memory(
                        "failed episode plan ownership or rendering differs",
                    ));
                }
                reader.verify_children(&published_plan)?;
                plans.insert(
                    record.plan_id.clone(),
                    (
                        plan,
                        published_plan.root,
                        ContentDigest::sha256(&published_plan.record),
                    ),
                );
            }
            let (plan, plan_root, plan_record_digest) = plans
                .get(&record.plan_id)
                .ok_or_else(|| invalid_memory("failed episode plan is absent"))?;
            if plan.mission_id != record.mission_id
                || plan.session_id != record.episode.session_id
                || plan.mission_id.as_str() != record.episode.objective_id
                || plan.operation_id != record.operation_id
                || record.episode.plan_digest != plan_record_digest.to_text()
                || record.episode.decision_digest != plan.control_plan_digest.to_text()
            {
                return Err(invalid_memory(
                    "failed episode does not bind its exact plan",
                ));
            }
            let cause = AttributionCauseClass::Execution;
            let target = target_json(&FeedbackTarget::Event(plan.event_id.clone()));
            let bucket = buckets.entry((target, cause.as_str())).or_default();
            bucket.cause_class = Some(cause);
            let mut roots = vec![
                published.root,
                *plan_root,
                *plan_record_digest,
                plan.control_plan_digest,
            ];
            for receipt in &record.episode.effect_receipts {
                if let Ok(digest) = ContentDigest::parse(receipt) {
                    roots.push(digest);
                }
            }
            add_record(
                bucket,
                record.episode.episode_id,
                record.recorded_at.0,
                reference_time_ns,
                roots,
            )?;
        }
    }

    let mut warnings = Vec::new();
    for ((target, _), bucket) in buckets {
        if bucket.record_ids.len() < TRAUMA_GUARD_MIN_NEGATIVE_COUNT {
            continue;
        }
        let cause = bucket
            .cause_class
            .ok_or_else(|| invalid_memory("missing attribution cause"))?;
        let record_ids: Vec<_> = bucket.record_ids.into_iter().collect();
        let warning = AntiPatternWarning {
            warning_id: warning_identity(&target, cause, &record_ids),
            target_json: target,
            cause_class: cause,
            negative_count: record_ids.len(),
            half_life_ns: TRAUMA_HALF_LIFE_NS,
            decay_weight_ppm: bucket.decay_weight_ppm,
            cited_record_ids: record_ids,
            cited_evidence_digests: bucket.digests.into_iter().collect(),
            active_policy_mutation: AntiPatternWarning::ACTIVE_POLICY_MUTATION,
        };
        warning
            .validate()
            .map_err(|_| invalid_memory("derived warning exceeds its canonical bounds"))?;
        warnings.push(warning);
        if warnings.len() > MAX_TRAUMA_WARNINGS {
            return Err(invalid_memory("warning-count bound exceeded"));
        }
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests;
