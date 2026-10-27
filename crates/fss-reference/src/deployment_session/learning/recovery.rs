#![forbid(unsafe_code)]
//! Strict historical decoding of the bounded, advisory learning capture profile.
//!
//! Recovery checks copied bytes and retained ownership links only. It never admits a live
//! session, renews a deadline, promotes learning, or treats a feedback label as physical truth.

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    BudgetVector, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractBasis, ContractError, EvidenceStrength, ExperienceCapsule,
    FeedbackPrivacyClass, KnowledgeState, KnownStatement, LearningProposal, LedgerAnchor,
    MissionId, PrincipalId, RequestedDisposition, SessionId,
};
use fss_object::ObjectManifest;

use super::{
    CAPTURE_DOMAIN, COST_UNKNOWN, EFFICACY_UNKNOWN, MAX_CAPTURE_OBJECTS, MAX_PROFILE_ITEMS,
    MAX_RECORD_BYTES, MAX_SOURCE_BYTES, MAX_SOURCE_OBJECTS, Sources, compile, other_children,
};
use crate::agent_session::checkpoint::journal::SessionRecoveryState;
use crate::deployment_session::{
    MissionRecord,
    episode::{EpisodeRecord, PublishedEpisode, TerminalOutcome},
    feedback::{FeedbackTarget, decode_proposal, render_json, target_json},
    plan::PlanRecord,
};

fn invalid() -> ContractError {
    ContractError::DigestMismatch
}

fn text(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<String, ContractError> {
    let value = d.text()?;
    if value.is_empty() || value.len() > maximum {
        return Err(ContractError::CountBoundExceeded);
    }
    Ok(value.to_owned())
}

fn portable(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b":._+/-".contains(&b))
}

fn identifier(d: &mut CanonicalDecoder<'_>) -> Result<String, ContractError> {
    let value = text(d, 256)?;
    if !portable(&value) {
        return Err(ContractError::InvalidIdentifier);
    }
    Ok(value)
}

fn count(d: &mut CanonicalDecoder<'_>, maximum: usize) -> Result<usize, ContractError> {
    let value = d.u32()? as usize;
    if value > maximum {
        return Err(ContractError::CountBoundExceeded);
    }
    Ok(value)
}

fn texts(
    d: &mut CanonicalDecoder<'_>,
    maximum_count: usize,
    maximum_bytes: usize,
    identifiers: bool,
) -> Result<Vec<String>, ContractError> {
    let length = count(d, maximum_count)?;
    let mut out = Vec::with_capacity(length);
    for _ in 0..length {
        let value = text(d, maximum_bytes)?;
        if identifiers && !portable(&value) {
            return Err(ContractError::InvalidIdentifier);
        }
        out.push(value);
    }
    Ok(out)
}

/// Decode exactly the experience profile the native capture producer publishes.
pub(crate) fn decode_experience(bytes: &[u8]) -> Result<ExperienceCapsule, ContractError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ContractError::CountBoundExceeded);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != ExperienceCapsule::SCHEMA {
        return Err(invalid());
    }
    let experience_id = identifier(&mut d)?;
    let suffix = experience_id
        .strip_prefix("experience:")
        .ok_or_else(invalid)?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    let mission_id = MissionId::decode_canonical(&mut d)?;
    let deployment_scope = texts(&mut d, MAX_PROFILE_ITEMS, 256, true)?;
    let basis_anchor = LedgerAnchor::decode_canonical(&mut d)?;
    let signature = text(&mut d, 73)?;
    let digest_text = signature
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(invalid)?;
    let signature_digest = ContentDigest::parse(digest_text)?;
    if !digest_text.starts_with("sha256:")
        || signature != format!("\"{}\"", signature_digest.to_text())
    {
        return Err(invalid());
    }
    let objective = text(&mut d, 4096)?;
    let statement_count = count(&mut d, MAX_PROFILE_ITEMS)?;
    let mut initial = Vec::with_capacity(statement_count);
    let mut identities = BTreeSet::new();
    for _ in 0..statement_count {
        let statement_id = identifier(&mut d)?;
        if !identities.insert(statement_id.clone()) {
            return Err(invalid());
        }
        initial.push(KnownStatement {
            statement_id,
            text: text(&mut d, 8192)?,
            epistemic_state: KnowledgeState::decode_canonical(&mut d)?,
            basis: texts(&mut d, 256, 256, true)?,
        });
    }
    let operations = texts(&mut d, 512, 256, true)?;
    let outcome = text(&mut d, 8192)?;
    let predictive = texts(&mut d, 256, 1024, false)?;
    let misleading = texts(&mut d, 256, 1024, false)?;
    let failed = texts(&mut d, 256, 256, true)?;
    let cost = <BudgetVector as CanonicalDecode>::decode_canonical(&mut d)?;
    let applicability = texts(&mut d, MAX_PROFILE_ITEMS, 1024, false)?;
    if d.text()? != EvidenceStrength::SingleEpisode.as_str() {
        return Err(invalid());
    }
    let confidence = d.u32()?;
    let half_life = d.u32()?;
    let privacy = text(&mut d, 1024)?;
    let created_at = d.i128()?;
    d.ensure_finished()?;
    if deployment_scope.len() != 1
        || deployment_scope[0] != basis_anchor.site_lineage
        || operations.len() != 1
        || !predictive.is_empty()
        || !misleading.is_empty()
        || !failed.is_empty()
        || cost != BudgetVector::ZERO
        || applicability.is_empty()
        || confidence != 0
        || half_life != 30
        || privacy != "private"
        || created_at < 0
        || initial.len() < 2
    {
        return Err(invalid());
    }
    let cost_unknown = &initial[initial.len() - 2];
    let efficacy_unknown = &initial[initial.len() - 1];
    if cost_unknown.statement_id != "unknown:learning-cost"
        || cost_unknown.text != COST_UNKNOWN
        || cost_unknown.epistemic_state != KnowledgeState::Unknown
        || cost_unknown.basis.len() != 1
        || efficacy_unknown.statement_id != "unknown:learning-efficacy"
        || efficacy_unknown.text != EFFICACY_UNKNOWN
        || efficacy_unknown.epistemic_state != KnowledgeState::Unknown
        || efficacy_unknown.basis.len() != 3
        || initial[..initial.len() - 2].iter().any(|statement| {
            statement.epistemic_state != KnowledgeState::Estimated || statement.basis.len() != 1
        })
        || initial
            .iter()
            .flat_map(|statement| &statement.basis)
            .any(|value| ContentDigest::parse(value).is_err())
    {
        return Err(invalid());
    }
    let experience = ExperienceCapsule::new(
        experience_id,
        mission_id,
        deployment_scope,
        basis_anchor,
        signature,
        objective,
        initial,
        operations,
        outcome,
        predictive,
        misleading,
        failed,
        cost,
        applicability,
        EvidenceStrength::SingleEpisode,
        confidence,
        half_life,
        privacy,
        created_at,
    )?;
    if experience.try_canonical_bytes()? != bytes {
        return Err(invalid());
    }
    Ok(experience)
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CaptureBinding {
    pub(crate) contract_basis: ContractBasis,
    pub(crate) session_id: SessionId,
    pub(crate) mission_id: MissionId,
    pub(crate) principal: PrincipalId,
    pub(crate) workspace_digest: ContentDigest,
    pub(crate) mission_digest: ContentDigest,
    pub(crate) feedback_root: ContentDigest,
    pub(crate) plan_root: ContentDigest,
    pub(crate) episode_root: ContentDigest,
    pub(crate) experience_digest: ContentDigest,
    pub(crate) proposal_digest: ContentDigest,
    pub(crate) evidence: Vec<ContentDigest>,
    pub(crate) missing_evidence: Vec<String>,
}

/// Fully checked historical learning data; it grants no live admission or activation.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct VerifiedLearning {
    pub(crate) binding: CaptureBinding,
    pub(crate) experience: ExperienceCapsule,
    pub(crate) proposal: LearningProposal,
}

fn decode_basis(bytes: &[u8]) -> Result<ContractBasis, ContractError> {
    let mut d = CanonicalDecoder::new(bytes);
    let basis = ContractBasis {
        semantic_protocol: text(&mut d, 128)?,
        schema_catalog_digest: d.digest()?,
        ontology_generation_id: text(&mut d, 4096)?,
        operation_registry_digest: d.digest()?,
        view_registry_digest: d.digest()?,
        capability_registry_digest: d.digest()?,
        error_registry_digest: d.digest()?,
        cost_registry_digest: d.digest()?,
        producer_release_id: text(&mut d, 4096)?,
        accepted_nightly: if d.bool()? {
            Some(text(&mut d, 4096)?)
        } else {
            None
        },
    };
    d.ensure_finished()?;
    basis.validate()?;
    if basis.semantic_protocol != "fss/1" || basis.try_canonical_bytes()? != bytes {
        return Err(invalid());
    }
    Ok(basis)
}

impl CaptureBinding {
    fn to_bytes(&self) -> Result<Vec<u8>, ContractError> {
        let mut e = CanonicalEncoder::new();
        e.text(CAPTURE_DOMAIN);
        e.bytes(&self.contract_basis.try_canonical_bytes()?);
        self.session_id.encode_canonical(&mut e);
        self.mission_id.encode_canonical(&mut e);
        self.principal.encode_canonical(&mut e);
        e.digest(self.workspace_digest);
        e.digest(self.mission_digest);
        e.digest(self.feedback_root);
        e.digest(self.plan_root);
        e.digest(self.episode_root);
        e.digest(self.experience_digest);
        e.digest(self.proposal_digest);
        e.u32(self.evidence.len() as u32);
        for digest in &self.evidence {
            e.digest(*digest);
        }
        e.u32(self.missing_evidence.len() as u32);
        for missing in &self.missing_evidence {
            e.text(missing);
        }
        Ok(e.finish())
    }
}

/// Reused by exact retries to authenticate the original retained workspace binding.
pub(super) fn decode_binding(bytes: &[u8]) -> Result<CaptureBinding, ContractError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ContractError::CountBoundExceeded);
    }
    let mut d = CanonicalDecoder::new(bytes);
    if d.text()? != CAPTURE_DOMAIN {
        return Err(invalid());
    }
    let basis_bytes = d.bytes()?;
    if basis_bytes.len() > 16_384 {
        return Err(ContractError::CountBoundExceeded);
    }
    let mut binding = CaptureBinding {
        contract_basis: decode_basis(basis_bytes)?,
        session_id: SessionId::decode_canonical(&mut d)?,
        mission_id: MissionId::decode_canonical(&mut d)?,
        principal: PrincipalId::parse(text(&mut d, 4096)?)?,
        workspace_digest: d.digest()?,
        mission_digest: d.digest()?,
        feedback_root: d.digest()?,
        plan_root: d.digest()?,
        episode_root: d.digest()?,
        experience_digest: d.digest()?,
        proposal_digest: d.digest()?,
        evidence: Vec::new(),
        missing_evidence: Vec::new(),
    };
    let evidence_count = count(&mut d, MAX_SOURCE_OBJECTS + 8)?;
    for _ in 0..evidence_count {
        binding.evidence.push(d.digest()?);
    }
    binding.missing_evidence = texts(&mut d, MAX_PROFILE_ITEMS, 1024, false)?;
    d.ensure_finished()?;
    if binding.evidence.is_empty()
        || binding.evidence.windows(2).any(|pair| pair[0] >= pair[1])
        || binding.missing_evidence.first().map(String::as_str) != Some(COST_UNKNOWN)
        || binding.missing_evidence.get(1).map(String::as_str) != Some(EFFICACY_UNKNOWN)
        || binding.to_bytes()? != bytes
    {
        return Err(invalid());
    }
    Ok(binding)
}

fn graph(
    objects: &BTreeMap<ContentDigest, Vec<u8>>,
    root: ContentDigest,
    kind: &str,
    used: &mut BTreeSet<ContentDigest>,
) -> Result<ObjectManifest, ContractError> {
    let manifest = ObjectManifest::from_canonical_bytes(objects.get(&root).ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    if manifest.root() != root || manifest.kind() != kind {
        return Err(invalid());
    }
    used.insert(root);
    for digest in manifest.children() {
        if !objects.contains_key(digest) {
            return Err(invalid());
        }
        used.insert(*digest);
    }
    Ok(manifest)
}

fn record_bytes<'a>(
    objects: &'a BTreeMap<ContentDigest, Vec<u8>>,
    manifest: &ObjectManifest,
) -> Result<&'a [u8], ContractError> {
    let digest = manifest.metadata_digest().ok_or_else(invalid)?;
    Ok(objects.get(&digest).ok_or_else(invalid)?.as_slice())
}

/// Verify a copied graph against its original retained workspace and canonical source owners.
/// All bytes are supplied by the caller's bounded recovery I/O; this function performs no I/O.
pub(crate) fn verify_recovery_closure(
    experience: &ExperienceCapsule,
    metadata: ContentDigest,
    objects: &BTreeMap<ContentDigest, Vec<u8>>,
    sessions: &SessionRecoveryState,
) -> Result<VerifiedLearning, ContractError> {
    if objects.len() > MAX_CAPTURE_OBJECTS
        || objects
            .values()
            .try_fold(0_usize, |sum, bytes| sum.checked_add(bytes.len()))
            .is_none_or(|size| size > MAX_SOURCE_BYTES + 2 * MAX_RECORD_BYTES)
        || objects
            .iter()
            .any(|(digest, bytes)| ContentDigest::sha256(bytes) != *digest)
        || objects.get(&metadata).map(Vec::as_slice)
            != Some(experience.try_canonical_bytes()?.as_slice())
    {
        return Err(invalid());
    }
    let mut binding_objects = objects.iter().filter(|(_, bytes)| {
        CanonicalDecoder::new(bytes)
            .text()
            .is_ok_and(|domain| domain == CAPTURE_DOMAIN)
    });
    let (binding_digest, binding_bytes) = binding_objects.next().ok_or_else(invalid)?;
    if binding_objects.next().is_some() {
        return Err(invalid());
    }
    let binding = decode_binding(binding_bytes)?;
    if binding.experience_digest != metadata {
        return Err(invalid());
    }
    let retained = sessions
        .sessions
        .iter()
        .find(|entry| entry.session.session_id == binding.session_id)
        .ok_or_else(invalid)?;
    let workspace = sessions
        .workspace_revisions
        .iter()
        .find(|revision| revision.digest() == binding.workspace_digest)
        .ok_or_else(invalid)?;
    if retained.session.principal_id != binding.principal
        || retained.session.mission_id != binding.mission_id
        || workspace.capsule().session_id != binding.session_id
        || workspace.capsule().principal != binding.principal.as_str()
        || workspace.capsule().objective_digest != binding.mission_digest.to_text()
        || workspace.contract_basis() != &binding.contract_basis
    {
        return Err(invalid());
    }

    let mut used = BTreeSet::new();
    let plan_manifest = graph(objects, binding.plan_root, "agent-plan", &mut used)?;
    let plan = PlanRecord::from_bytes(record_bytes(objects, &plan_manifest)?)?;
    let episode_manifest = graph(objects, binding.episode_root, "agent-episode", &mut used)?;
    let episode_record = EpisodeRecord::from_bytes(record_bytes(objects, &episode_manifest)?)?;
    let episode_renderings = other_children(&episode_manifest);
    let [rendering] = episode_renderings.as_slice() else {
        return Err(invalid());
    };
    let episode = PublishedEpisode {
        record: episode_record,
        root: binding.episode_root,
        rendering: *rendering,
    };
    let feedback_manifest = graph(objects, binding.feedback_root, "agent-feedback", &mut used)?;
    let feedback = decode_proposal(record_bytes(objects, &feedback_manifest)?)?;
    let mission_root =
        ObjectManifest::new("agent-mission", Vec::new(), Some(binding.mission_digest))
            .map_err(|_| invalid())?
            .root();
    let mission_manifest = graph(objects, mission_root, "agent-mission", &mut used)?;
    let mission = MissionRecord::from_bytes(record_bytes(objects, &mission_manifest)?)?;
    if plan.plan_id
        != PlanRecord::identity(&plan.session_id, &plan.anchor_token, plan.plan_approval)
        || plan.session_id != binding.session_id
        || plan.mission_id != binding.mission_id
        || plan.principal != binding.principal
        || other_children(&plan_manifest) != [plan.control_plan_digest]
        || mission.digest() != binding.mission_digest
        || mission.session_id != binding.session_id
        || mission.mission_id != binding.mission_id
        || mission.principal != binding.principal
        || !other_children(&mission_manifest).is_empty()
        || feedback.session_id != binding.session_id
        || feedback.principal_id != binding.principal
        || feedback.basis_anchor != workspace.capsule().current_anchor
        || feedback.target_json != target_json(&FeedbackTarget::Plan(plan.plan_id.clone()))
        || feedback.privacy_class != FeedbackPrivacyClass::Private
        || feedback.requested_disposition != RequestedDisposition::CreateLearningProposal
        || other_children(&feedback_manifest)
            != [ContentDigest::sha256(render_json(&feedback).as_bytes())]
    {
        return Err(invalid());
    }
    let record = &episode.record;
    let executed = &record.episode;
    if record.plan_id != plan.plan_id
        || record.principal != plan.principal
        || record.mission_id != plan.mission_id
        || record.operation_id != plan.operation_id
        || executed.session_id != plan.session_id
        || executed.objective_id != plan.mission_id.as_str()
        || executed.plan_digest != ContentDigest::sha256(&plan.to_bytes()).to_text()
        || executed.decision_digest != plan.control_plan_digest.to_text()
        || !executed
            .outcome
            .indeterminate_predicates
            .iter()
            .any(|value| value == "warranted")
    {
        return Err(invalid());
    }
    let terminal_matches = match record.terminal_state {
        TerminalOutcome::Verified => {
            matches!(
                executed.outcome.state.as_str(),
                "succeeded" | "partially_succeeded"
            ) && executed
                .outcome
                .success_predicates
                .iter()
                .any(|value| value == "delivered")
        }
        TerminalOutcome::Failed => {
            executed.outcome.state.as_str() == "failed"
                && executed
                    .outcome
                    .failed_predicates
                    .iter()
                    .any(|value| value == "delivered")
        }
        TerminalOutcome::Cancelled | TerminalOutcome::Withdrawn => {
            executed.outcome.state.as_str() == "cancelled"
        }
    };
    if !terminal_matches {
        return Err(invalid());
    }
    let mut expected_evidence = used.clone();
    expected_evidence.extend([
        executed.initial_anchor.state_root,
        executed.terminal_anchor.state_root,
    ]);
    if record.terminal_state == TerminalOutcome::Withdrawn {
        if !executed.effect_receipts.is_empty() || !executed.obligations.is_empty() {
            return Err(invalid());
        }
    } else {
        let [receipt, result, proof] = executed.effect_receipts.as_slice() else {
            return Err(invalid());
        };
        let receipt = ContentDigest::parse(
            receipt
                .strip_prefix("operation-receipt:")
                .ok_or_else(invalid)?,
        )?;
        let result = ContentDigest::parse(result.strip_prefix("result:").ok_or_else(invalid)?)?;
        let proof = ContentDigest::parse(
            proof
                .strip_prefix("obligation-proof:")
                .ok_or_else(invalid)?,
        )?;
        if result != proof
            || executed.obligations
                != [format!(
                    "{}={}",
                    plan.obligation_id,
                    record.terminal_state.as_str()
                )]
        {
            return Err(invalid());
        }
        expected_evidence.extend([receipt, result, proof]);
    }
    if binding.evidence != expected_evidence.iter().copied().collect::<Vec<_>>()
        || feedback
            .supporting_evidence
            .iter()
            .chain(&feedback.contradicting_evidence)
            .any(|value| {
                ContentDigest::parse(value)
                    .map_or(true, |digest| !expected_evidence.contains(&digest))
            })
    {
        return Err(invalid());
    }
    let expected = compile(&Sources {
        feedback: &feedback,
        feedback_root: binding.feedback_root,
        plan: &plan,
        plan_root: binding.plan_root,
        episode: &episode,
        mission: &mission,
        evidence: binding.evidence.clone(),
    })
    .map_err(|_| invalid())?;
    let proposal_bytes = expected.proposal.try_canonical_bytes()?;
    if expected.experience != *experience
        || expected.missing_evidence != binding.missing_evidence
        || ContentDigest::sha256(&proposal_bytes) != binding.proposal_digest
        || objects.get(&binding.proposal_digest).map(Vec::as_slice)
            != Some(proposal_bytes.as_slice())
    {
        return Err(invalid());
    }
    used.extend([metadata, *binding_digest, binding.proposal_digest]);
    if used != objects.keys().copied().collect() {
        return Err(invalid());
    }
    Ok(VerifiedLearning {
        binding,
        experience: expected.experience,
        proposal: expected.proposal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<ExperienceCapsule, ContractError> {
        let root = ContentDigest::sha256(b"retained source root").to_text();
        ExperienceCapsule::new(
            "experience:00000000000000000000000000000000",
            MissionId::parse("mission:learning-recovery")?,
            vec!["site:learning-recovery".to_owned()],
            LedgerAnchor::genesis("site:learning-recovery"),
            format!("\"{root}\""),
            "Retain the uncertainty of an execution outcome.",
            vec![
                KnownStatement {
                    statement_id: "unknown:learning-cost".to_owned(),
                    text: COST_UNKNOWN.to_owned(),
                    epistemic_state: KnowledgeState::Unknown,
                    basis: vec![root.clone()],
                },
                KnownStatement {
                    statement_id: "unknown:learning-efficacy".to_owned(),
                    text: EFFICACY_UNKNOWN.to_owned(),
                    epistemic_state: KnowledgeState::Unknown,
                    basis: vec![root.clone(), root.clone(), root],
                },
            ],
            vec!["operation:learning-recovery".to_owned()],
            "Cancelled; the underlying event remains unestablished.",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            BudgetVector::ZERO,
            vec!["Only this historical source episode is in scope.".to_owned()],
            EvidenceStrength::SingleEpisode,
            0,
            30,
            "private",
            1,
        )
    }

    #[test]
    fn canonical_experience_recovery_refuses_truncation_trailing_bytes_and_false_certainty()
    -> Result<(), ContractError> {
        let experience = fixture()?;
        let bytes = experience.try_canonical_bytes()?;
        assert_eq!(decode_experience(&bytes)?, experience);
        for end in 0..bytes.len() {
            assert!(
                decode_experience(&bytes[..end]).is_err(),
                "accepted cut {end}"
            );
        }
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(decode_experience(&extended).is_err());
        let mut promoted = experience.clone();
        promoted.evidence_strength = EvidenceStrength::Proven;
        assert!(decode_experience(&promoted.try_canonical_bytes()?).is_err());
        let mut overconfident = experience.clone();
        overconfident.confidence_numerator = 1;
        assert!(decode_experience(&overconfident.try_canonical_bytes()?).is_err());
        let mut hidden_cost = experience;
        hidden_cost.initial_epistemic_map[0].epistemic_state = KnowledgeState::Known;
        assert!(decode_experience(&hidden_cost.try_canonical_bytes()?).is_err());
        Ok(())
    }
}
