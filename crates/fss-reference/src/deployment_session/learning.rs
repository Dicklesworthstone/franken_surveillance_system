#![forbid(unsafe_code)]
//! Captured, outcome-attributed advisory learning from an immutable closed plan (AOP-013).
//!
//! The original feedback publication remains immutable. An explicit plan-targeted
//! create-learning disposition publishes a separate root containing the canonical experience,
//! learning proposal, source binding, and complete verified plan/episode/feedback/mission graphs.
//! No promotion, policy mutation, effect, or assertion of physical-event truth occurs here.
//! Cost values are certified lower bounds; unmetered cost is retained as canonical uncertainty.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::{
    AgentFeedbackProposal, BudgetVector, CanonicalDecoder, CanonicalEncode, CanonicalEncoder,
    ContentDigest, ContractBasis, EvidenceStrength, ExperienceCapsule, FeedbackProposalKind,
    KnowledgeState, KnownStatement, LearningClass, LearningProposal,
};
use fss_object::ObjectManifest;
use fss_publication::SlotName;

use super::episode::PublishedEpisode;
use super::feedback::{FeedbackRequest, FeedbackTarget, PublishedFeedback, render_json};
use super::plan::{PlanRecord, read_control_plan};
use super::{
    DeploymentHistory, DeploymentSessionError, MAX_RECORD_BYTES, MissionRecord,
    PUBLICATIONS_RELPATH, SessionPosition, digest_of, hex, mission_for_workspace, operation_facts,
    publish_record, read_published,
};
use crate::agent_follow::{AnchorToken, resolve_anchor};
use crate::agent_orient::{DeploymentSnapshot, HistoryPosition};
use crate::agent_session::checkpoint::journal::DurableSessionStore;

const IDENTITY_DOMAIN: &str = "fss.reference_agent_learning_identity.v1";
const CAPTURE_DOMAIN: &str = "fss.reference_agent_learning_capture.v1";
const DECISION_DOMAIN: &str = "fss.reference_agent_learning_decision.v1";
const MAX_SOURCE_OBJECTS: usize = 64;
/// Complete source graph plus canonical proposal, capture binding and experience metadata.
pub(crate) const MAX_CAPTURE_OBJECTS: usize = MAX_SOURCE_OBJECTS + 3;
const MAX_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROFILE_ITEMS: usize = 128;
/// Maximum unchanged statement retained by this bounded learning profile.
pub const MAX_LEARNING_STATEMENT_BYTES: usize = 8192;
const REVIEW_NS: i128 = 7 * 24 * 60 * 60 * 1_000_000_000;
const EXPIRY_NS: i128 = 30 * 24 * 60 * 60 * 1_000_000_000;

pub(super) const COST_UNKNOWN: &str = "The cost vector contains certified lower bounds only. Full latency, tokens, bytes, model calls, CPU, accelerator work, energy, network, storage operations, privacy exposure and operator attention were not metered; zero lower bounds do not mean zero actual cost.";
pub(super) const EFFICACY_UNKNOWN: &str = "One retained execution episode and an agent's feedback do not establish causal effectiveness, helpfulness, harmfulness, or that the underlying surveillance event was real.";

/// An immutable, captured experience and its outcome-attributed learning proposal.
#[derive(Clone, Debug, PartialEq)]
pub struct PublishedLearning {
    /// Contract basis under which the source session admitted the capture.
    pub contract_basis: ContractBasis,
    /// Registered experience payload; cost fields are explicitly qualified lower bounds.
    pub experience: ExperienceCapsule,
    /// Registered advisory proposal; always captured with uncalibrated confidence.
    pub proposal: LearningProposal,
    /// Root of the complete immutable learning publication.
    pub root: ContentDigest,
    /// SHA-256 of the canonical experience bytes (publication metadata).
    pub experience_digest: ContentDigest,
    /// SHA-256 of the canonical learning-proposal child bytes.
    pub proposal_digest: ContentDigest,
    /// Original, authenticated episode publication root.
    pub episode_root: ContentDigest,
    /// Original feedback publication root, unchanged by capture.
    pub feedback_root: ContentDigest,
    /// Original plan publication root.
    pub plan_root: ContentDigest,
    /// Whether this call published the learning root.
    pub committed: bool,
    /// Mandatory uncertainty disclosure for the experience's missingEvidence projection.
    pub missing_evidence: Vec<String>,
    /// Verified source and receipt digests; no arbitrary caller-supplied digest is admitted.
    pub evidence: Vec<ContentDigest>,
    /// Exact original episode resource-use record, never replaced with a fabricated total.
    pub original_resource_use_json: String,
}

fn refused(reason: impl Into<String>) -> DeploymentSessionError {
    DeploymentSessionError::FeedbackRefused(reason.into())
}

fn invalid(reason: impl Into<String>) -> DeploymentSessionError {
    DeploymentSessionError::StoreInvalid(reason.into())
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_strings(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|s| json_string(s))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn learning_class(kind: FeedbackProposalKind) -> LearningClass {
    match kind {
        FeedbackProposalKind::Correction | FeedbackProposalKind::Adjudication => {
            LearningClass::FactCandidate
        }
        FeedbackProposalKind::Helpful | FeedbackProposalKind::RunbookCandidate => {
            LearningClass::ProcedureCandidate
        }
        FeedbackProposalKind::Harmful => LearningClass::AntiPatternCandidate,
        FeedbackProposalKind::MissingEvidence
        | FeedbackProposalKind::BadAffordance
        | FeedbackProposalKind::BadSummary => LearningClass::DiagnosticSignature,
        FeedbackProposalKind::AdapterQuirk => LearningClass::AdapterQuirk,
        FeedbackProposalKind::HardNegativeCandidate => LearningClass::BenchmarkFixtureCandidate,
        FeedbackProposalKind::PolicyCandidate => LearningClass::PolicyReviewCandidate,
        FeedbackProposalKind::ModelCandidate => LearningClass::ModelFailureMode,
    }
}

fn bounded_texts(values: &[String], maximum_bytes: usize) -> Result<(), DeploymentSessionError> {
    if values.len() > MAX_PROFILE_ITEMS
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > maximum_bytes)
    {
        return Err(refused(
            "complete learning context exceeds the bounded capture profile",
        ));
    }
    Ok(())
}

/// Read a known publication and every direct source object. The native plan, episode and
/// feedback readers separately verify the exact expected graph shape and record semantics.
fn source_graph(
    root: &Path,
    publication_root: ContentDigest,
    objects: &mut BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<ObjectManifest, DeploymentSessionError> {
    let exhausted =
        || refused("the complete learning source closure exceeds its object or byte bound");
    let mut retained_bytes = objects
        .values()
        .try_fold(0_usize, |sum, bytes| sum.checked_add(bytes.len()))
        .ok_or_else(exhausted)?;
    if objects.len() > MAX_SOURCE_OBJECTS || retained_bytes > MAX_SOURCE_BYTES {
        return Err(exhausted());
    }
    let new_root = !objects.contains_key(&publication_root);
    if new_root && objects.len() == MAX_SOURCE_OBJECTS {
        return Err(exhausted());
    }
    let directory = root.join(PUBLICATIONS_RELPATH);
    let bytes = match objects.get(&publication_root) {
        Some(bytes) => bytes.clone(),
        None => fss_publication::read_verified(
            &directory,
            publication_root,
            MAX_RECORD_BYTES.min(MAX_SOURCE_BYTES - retained_bytes),
        )
        .map_err(|_| invalid("a learning source publication root is unavailable or corrupt"))?,
    };
    let manifest = ObjectManifest::from_canonical_bytes(&bytes)
        .map_err(|_| invalid("a learning source publication manifest does not verify"))?;
    if manifest.root() != publication_root {
        return Err(invalid("a learning source publication has another root"));
    }
    // Reject an oversized manifest before attempting any of its child reads.
    let additional = usize::from(new_root)
        + manifest
            .children()
            .iter()
            .filter(|digest| **digest != publication_root && !objects.contains_key(*digest))
            .count();
    if additional > MAX_SOURCE_OBJECTS - objects.len() {
        return Err(exhausted());
    }
    if new_root {
        retained_bytes = retained_bytes
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_SOURCE_BYTES)
            .ok_or_else(exhausted)?;
        objects.insert(publication_root, bytes);
    }
    for digest in manifest.children() {
        if !objects.contains_key(digest) {
            if objects.len() == MAX_SOURCE_OBJECTS || retained_bytes == MAX_SOURCE_BYTES {
                return Err(exhausted());
            }
            let bytes = fss_publication::read_verified(
                &directory,
                *digest,
                MAX_RECORD_BYTES.min(MAX_SOURCE_BYTES - retained_bytes),
            )
            .map_err(|_| {
                invalid("a learning source publication child is unavailable or corrupt")
            })?;
            retained_bytes = retained_bytes
                .checked_add(bytes.len())
                .filter(|size| *size <= MAX_SOURCE_BYTES)
                .ok_or_else(exhausted)?;
            objects.insert(*digest, bytes);
        }
    }
    Ok(manifest)
}

fn other_children(manifest: &ObjectManifest) -> Vec<ContentDigest> {
    manifest
        .children()
        .iter()
        .copied()
        .filter(|digest| Some(*digest) != manifest.metadata_digest())
        .collect()
}

fn retained_anchor(history: &DeploymentHistory, anchor: &fss_core::LedgerAnchor) -> bool {
    history
        .roots_at(HistoryPosition {
            commit_sequence: anchor.commit_sequence,
            effect_records: history.head().effect_records,
        })
        .is_some_and(|(retained, _, _)| retained == *anchor)
}

struct Sources<'a> {
    feedback: &'a AgentFeedbackProposal,
    feedback_root: ContentDigest,
    plan: &'a PlanRecord,
    plan_root: ContentDigest,
    episode: &'a PublishedEpisode,
    mission: &'a MissionRecord,
    evidence: Vec<ContentDigest>,
}

struct Blueprint {
    experience: ExperienceCapsule,
    proposal: LearningProposal,
    missing_evidence: Vec<String>,
}

/// Compile only the admitted single-episode profile. Feedback labels remain allegations:
/// neither their kind nor the effect outcome increments helpful/harmful counts or confidence.
fn compile(sources: &Sources<'_>) -> Result<Blueprint, DeploymentSessionError> {
    let feedback = sources.feedback;
    let episode = &sources.episode.record.episode;
    if feedback.statement.is_empty() || feedback.statement.len() > MAX_LEARNING_STATEMENT_BYTES {
        return Err(refused(
            "learning statements must be 1..=8192 bytes; feedback remains retained",
        ));
    }
    if episode.predictions.len() > MAX_PROFILE_ITEMS - 2 {
        return Err(refused(
            "the complete source predictions exceed the learning profile",
        ));
    }
    bounded_texts(&episode.residual_uncertainty, 4096)?;
    let created_at = feedback
        .created_at_ns
        .max(sources.episode.record.recorded_at.0);
    if created_at < 0 {
        return Err(refused(
            "learning capture requires nonnegative retained source time",
        ));
    }
    let review_after = created_at
        .checked_add(REVIEW_NS)
        .ok_or_else(|| refused("learning review time exceeds the evidence clock range"))?;
    let expiry = created_at
        .checked_add(EXPIRY_NS)
        .ok_or_else(|| refused("learning expiry exceeds the evidence clock range"))?;
    let identity = digest_of(IDENTITY_DOMAIN, |encoder| {
        encoder.digest(sources.feedback_root);
        encoder.text(&feedback.feedback_id);
    });
    let identity_hex = hex(identity);
    let suffix: String = identity_hex.chars().take(32).collect();
    let source_roots = vec![
        sources.feedback_root.to_text(),
        sources.plan_root.to_text(),
        sources.episode.root.to_text(),
    ];
    let exclusions = vec![
        "No active policy, model, threshold, identity, retention, privacy, capability or effect changes are authorized.".to_owned(),
        "Do not infer physical-event truth, causal efficacy, helpfulness or harmfulness from an effect outcome or feedback label.".to_owned(),
        "Do not generalize beyond the exact source deployment, plan, episode and authority generations without independent validation.".to_owned(),
        "Cost-model or policy use requires complete resource metering and held-out validation.".to_owned(),
    ];
    let preconditions = vec![
        format!("Exact source plan {} and immutable episode {}.", sources.plan.plan_id, episode.episode_id),
        format!("Original source anchor {} and terminal anchor {}.", episode.initial_anchor.state_root, episode.terminal_anchor.state_root),
        "Only an unvalidated, advisory single-episode capture; original predictions and residual uncertainty remain authoritative.".to_owned(),
    ];
    let applicability_json = format!(
        "{{\"calibrationGenerations\":[],\"deployment\":{},\"deviceTuples\":[],\"exclusions\":{},\"modelGenerations\":[],\"preconditions\":{},\"timeConditions\":{}}}",
        json_strings(&[sources.mission.site_lineage.clone()]),
        json_strings(&exclusions),
        json_strings(&preconditions),
        json_strings(&[format!(
            "Review after evidence time {review_after} ns; expires at {expiry} ns. An exact retry never renews these deadlines."
        )]),
    );
    let decision = digest_of(DECISION_DOMAIN, |encoder| {
        encoder.digest(identity);
        encoder.text(&applicability_json);
        encoder.text(&feedback.statement);
        encoder.text(learning_class(feedback.kind).as_str());
        encoder.text(&episode.resource_use_json);
        encoder.text(COST_UNKNOWN);
        encoder.text(EFFICACY_UNKNOWN);
        for digest in &sources.evidence {
            encoder.digest(*digest);
        }
    });
    let mut supporting = feedback.supporting_evidence.clone();
    supporting.extend(source_roots.iter().cloned());
    supporting.sort();
    supporting.dedup();
    bounded_texts(&supporting, 1024)?;
    bounded_texts(&feedback.contradicting_evidence, 1024)?;
    let proposal = LearningProposal::record(
        format!("learning:{suffix}"),
        learning_class(feedback.kind),
        episode.episode_id.clone(),
        feedback.statement.clone(),
        applicability_json,
        supporting,
        feedback.contradicting_evidence.clone(),
        Vec::new(),
        0,
        0,
        0,
        vec![
            "Review the original predictions, execution receipts, feedback provenance, counterexamples and all residual uncertainty.".to_owned(),
            "Validate applicability and causal claims against independent held-out evidence, including harmful counterexamples.".to_owned(),
            "Measure the full resource vector before any cost-model comparison.".to_owned(),
            "Use a separate evidence-gated review, validation, shadow and promotion path; this captured record has no activation authority.".to_owned(),
        ],
        Some(review_after),
        Some(expiry),
        vec!["Re-admit source custody, current authority, applicability and new independent validation; an exact retry does not revive or promote this capture.".to_owned()],
        decision.to_text(),
    )?;
    let mut initial = Vec::with_capacity(episode.predictions.len() + 2);
    for prediction in &episode.predictions {
        let text = format!(
            "Original prediction: {} Expected state: {}.",
            prediction.statement, prediction.expected_state
        );
        if text.len() > 8192 {
            return Err(refused(
                "an original prediction exceeds the experience wire bound",
            ));
        }
        initial.push(KnownStatement {
            statement_id: prediction.prediction_id.clone(),
            text,
            epistemic_state: KnowledgeState::Estimated,
            basis: vec![sources.plan_root.to_text()],
        });
    }
    initial.push(KnownStatement {
        statement_id: "unknown:learning-cost".to_owned(),
        text: COST_UNKNOWN.to_owned(),
        epistemic_state: KnowledgeState::Unknown,
        basis: vec![sources.episode.root.to_text()],
    });
    initial.push(KnownStatement {
        statement_id: "unknown:learning-efficacy".to_owned(),
        text: EFFICACY_UNKNOWN.to_owned(),
        epistemic_state: KnowledgeState::Unknown,
        basis: source_roots.clone(),
    });
    // The episode's effectSpanNs is an evidence-clock interval, not a complete wall-clock
    // task latency measurement. Preserve it in the source graph and report only nonnegative
    // lower bounds here, with mandatory typed uncertainty for every unmetered dimension.
    let cost = BudgetVector::ZERO;
    let mut missing_evidence = vec![COST_UNKNOWN.to_owned(), EFFICACY_UNKNOWN.to_owned()];
    missing_evidence.extend(episode.residual_uncertainty.iter().cloned());
    // The optional wire missingEvidence strings are bounded to 1024 characters. Never truncate
    // a retained uncertainty to force a nominally successful experience.
    bounded_texts(&missing_evidence, 1024)?;
    let mut applicability = preconditions;
    applicability.extend(exclusions);
    let outcome = format!(
        "Retained execution episode {} reports {} for plan {} (operation {}). Indeterminate predicates: [{}]. The feedback statement remains an unvalidated proposal. Cost values are certified lower bounds only, with unmetered dimensions explicitly unknown.",
        episode.episode_id,
        episode.outcome.state.as_str(),
        sources.plan.plan_id,
        sources.plan.operation_id,
        episode.outcome.indeterminate_predicates.join(", "),
    );
    if outcome.len() > 8192 || sources.mission.objective.len() > 4096 {
        return Err(refused(
            "the immutable source objective or outcome exceeds the experience profile",
        ));
    }
    let experience = ExperienceCapsule::new(
        format!("experience:{suffix}"),
        sources.mission.mission_id.clone(),
        vec![sources.mission.site_lineage.clone()],
        episode.initial_anchor.clone(),
        json_string(&sources.plan_root.to_text()),
        sources.mission.objective.clone(),
        initial,
        vec![sources.plan.operation_id.clone()],
        outcome,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        cost,
        applicability,
        EvidenceStrength::SingleEpisode,
        0,
        30,
        "private",
        created_at,
    )?;
    // Keep the entire original epistemic source graph: empty signal/counterexample lists do
    // not assert that no signals or counterexamples exist.
    Ok(Blueprint {
        experience,
        proposal,
        missing_evidence,
    })
}

/// Called while the feedback command still holds its admitted session journal lock.
pub(super) fn capture(
    root: &Path,
    request: &FeedbackRequest,
    feedback: &PublishedFeedback,
    position: &SessionPosition,
    history: &DeploymentHistory,
    head: &DeploymentSnapshot,
    store: &mut DurableSessionStore,
) -> Result<PublishedLearning, DeploymentSessionError> {
    let FeedbackTarget::Plan(plan_id) = &request.target else {
        return Err(refused(
            "this bounded learning profile requires an explicit plan target",
        ));
    };
    let (plan, plan_root, _) = read_control_plan(root, plan_id)?;
    let session = &position.session;
    if plan.plan_id != *plan_id
        || plan.plan_id
            != PlanRecord::identity(&plan.session_id, &plan.anchor_token, plan.plan_approval)
        || plan.session_id != session.session_id
        || plan.mission_id != session.mission_id
        || plan.principal != session.principal_id
        || feedback.proposal.session_id != session.session_id
        || feedback.proposal.principal_id != session.principal_id
        || feedback.proposal.basis_anchor != session.current_anchor
    {
        return Err(refused(
            "the learning source plan and feedback must belong to this exact session, mission and principal",
        ));
    }
    if *position.workspace.contract_basis() != feedback.orientation.capsule().contract_basis {
        return Err(refused(
            "the learning source contract basis differs from the admitted workspace",
        ));
    }
    let mission = mission_for_workspace(root, session, &position.workspace)?;
    let facts = operation_facts(head, &plan.operation_id, &plan.obligation_id);
    let (_, episode) = super::mission::checked_episode(root, &plan, facts.as_ref())
        .map_err(|error| refused(format!("the retained execution episode cannot ground learning: {error}")))?
        .ok_or_else(|| refused("close the source plan to retain its terminal execution episode before capturing learning"))?;
    let token = AnchorToken::parse(&plan.anchor_token)
        .ok_or_else(|| refused("the source plan anchor is malformed"))?;
    let start = resolve_anchor(history, &token)
        .map_err(|_| refused("the source plan is no longer in this retained deployment history"))?;
    if history
        .roots_at(start)
        .is_none_or(|(anchor, _, _)| anchor != episode.record.episode.initial_anchor)
        || !retained_anchor(history, &episode.record.episode.terminal_anchor)
    {
        return Err(refused(
            "the source episode's initial or terminal evidence anchor is no longer retained",
        ));
    }
    let mut objects = BTreeMap::new();
    let plan_manifest = source_graph(root, plan_root, &mut objects)?;
    if plan_manifest.kind() != "agent-plan"
        || plan_manifest.metadata_digest() != Some(ContentDigest::sha256(&plan.to_bytes()))
        || other_children(&plan_manifest) != vec![plan.control_plan_digest]
    {
        return Err(invalid(
            "the learning plan publication differs from its exact record and rendering",
        ));
    }
    let episode_manifest = source_graph(root, episode.root, &mut objects)?;
    if episode_manifest.kind() != "agent-episode"
        || episode_manifest.metadata_digest()
            != Some(ContentDigest::sha256(&episode.record.to_bytes()))
        || other_children(&episode_manifest) != vec![episode.rendering]
    {
        return Err(invalid(
            "the learning episode publication differs from its exact record and rendering",
        ));
    }
    let feedback_manifest = source_graph(root, feedback.root, &mut objects)?;
    if feedback_manifest.kind() != "agent-feedback"
        || feedback_manifest.metadata_digest()
            != Some(ContentDigest::sha256(
                &feedback.proposal.try_canonical_bytes()?,
            ))
        || other_children(&feedback_manifest)
            != vec![ContentDigest::sha256(
                render_json(&feedback.proposal).as_bytes(),
            )]
    {
        return Err(invalid(
            "the original feedback publication differs from its exact admitted record",
        ));
    }
    let mission_publication = read_published(root, &MissionRecord::slot(mission.digest())?)?
        .ok_or_else(|| invalid("the original mission publication is missing"))?;
    if mission_publication.record != mission.to_bytes() || !mission_publication.children.is_empty()
    {
        return Err(invalid(
            "the original mission publication differs from its admitted record",
        ));
    }
    let mission_manifest = source_graph(root, mission_publication.root, &mut objects)?;
    if mission_manifest.kind() != "agent-mission" {
        return Err(invalid("the original mission publication has another kind"));
    }
    let mut evidence: BTreeSet<_> = objects.keys().copied().collect();
    evidence.extend([
        episode.record.episode.initial_anchor.state_root,
        episode.record.episode.terminal_anchor.state_root,
    ]);
    if let Some(facts) = &facts {
        evidence.insert(facts.receipt_digest);
        evidence.extend(facts.result_digest);
        evidence.extend(
            facts
                .obligation
                .as_ref()
                .and_then(|obligation| obligation.proof_digest),
        );
    }
    for handle in feedback
        .proposal
        .supporting_evidence
        .iter()
        .chain(&feedback.proposal.contradicting_evidence)
    {
        let digest = ContentDigest::parse(handle)?;
        if !evidence.contains(&digest) {
            return Err(refused(
                "learning evidence must belong to the exact retained plan, episode, feedback, mission or terminal-receipt closure",
            ));
        }
    }
    let effect_span_ns = facts
        .as_ref()
        .map_or(0, |facts| facts.effect_span_ns.max(0));
    let dispatched = facts.as_ref().is_some_and(|facts| facts.dispatched);
    let expected_resources = format!(
        "{{\"dispatches\":{},\"effectSpanNs\":{effect_span_ns}}}",
        u8::from(dispatched)
    );
    if episode.record.episode.resource_use_json != expected_resources {
        return Err(invalid(
            "the source episode resource-use record differs from its retained effect receipts",
        ));
    }
    let evidence: Vec<_> = evidence.into_iter().collect();
    let blueprint = compile(&Sources {
        feedback: &feedback.proposal,
        feedback_root: feedback.root,
        plan: &plan,
        plan_root,
        episode: &episode,
        mission: &mission,
        evidence: evidence.clone(),
    })?;
    let experience_bytes = blueprint.experience.canonical_bytes();
    decode_experience(&experience_bytes)?;
    let proposal_bytes = blueprint.proposal.canonical_bytes();
    let experience_digest = ContentDigest::sha256(&experience_bytes);
    let proposal_digest = ContentDigest::sha256(&proposal_bytes);
    let slot = SlotName::parse(&format!(
        "learning-{}",
        hex(ContentDigest::sha256(
            blueprint.experience.experience_id.as_bytes()
        ))
    ))
    .map_err(|_| invalid("the learning publication slot is invalid"))?;
    let existing = read_published(root, &slot)?;
    if existing.is_none()
        && captured_inventory(root, store, session, super::evidence_now(head))?
            .briefs
            .len()
            >= MAX_CAPTURED_LEARNING
    {
        return Err(refused(
            "the admitted captured-learning inventory is full; feedback remains retained and no new learning publication was started",
        ));
    }
    let workspace_digest = if let Some(existing) = &existing {
        // A benign workspace advance must not rewrite the original source binding. Recover
        // its exact historical workspace through the native owner under current admission.
        let mut retained = None;
        for child in &existing.children {
            let bytes = fss_publication::read_verified(
                root.join(PUBLICATIONS_RELPATH),
                *child,
                MAX_RECORD_BYTES,
            )
            .map_err(|_| invalid("a retained learning child is unavailable"))?;
            let mut decoder = CanonicalDecoder::new(&bytes);
            if decoder.text().ok() == Some(CAPTURE_DOMAIN) {
                if retained.is_some() {
                    return Err(invalid(
                        "the learning root contains multiple source bindings",
                    ));
                }
                retained = Some(recovery::decode_binding(&bytes)?);
            }
        }
        let retained =
            retained.ok_or_else(|| invalid("the learning root has no source binding"))?;
        let original = store
            .resume_workspace(
                &session.principal_id,
                &session.session_id,
                retained.workspace_digest,
                super::evidence_now(head),
            )?
            .result
            .revision;
        if original.contract_basis() != &retained.contract_basis
            || original.contract_basis() != position.workspace.contract_basis()
            || mission_for_workspace(root, session, &original)?.digest() != mission.digest()
        {
            return Err(refused(
                "the original learning workspace is no longer admitted under this mission and contract basis",
            ));
        }
        retained.workspace_digest
    } else {
        position.workspace.digest()
    };
    let mut binding = CanonicalEncoder::new();
    binding.text(CAPTURE_DOMAIN);
    binding.bytes(&position.workspace.contract_basis().try_canonical_bytes()?);
    session.session_id.encode_canonical(&mut binding);
    session.mission_id.encode_canonical(&mut binding);
    session.principal_id.encode_canonical(&mut binding);
    binding.digest(workspace_digest);
    binding.digest(mission.digest());
    binding.digest(feedback.root);
    binding.digest(plan_root);
    binding.digest(episode.root);
    binding.digest(experience_digest);
    binding.digest(proposal_digest);
    binding.u32(evidence.len() as u32);
    for digest in &evidence {
        binding.digest(*digest);
    }
    binding.u32(blueprint.missing_evidence.len() as u32);
    for missing in &blueprint.missing_evidence {
        binding.text(missing);
    }
    let binding_bytes = binding.finish();
    objects.insert(proposal_digest, proposal_bytes);
    objects.insert(ContentDigest::sha256(&binding_bytes), binding_bytes);
    let children: Vec<Vec<u8>> = objects.values().cloned().collect();
    let mut expected_children: Vec<_> = objects
        .keys()
        .copied()
        .filter(|digest| *digest != experience_digest)
        .collect();
    expected_children.sort_unstable();

    let verify = |published: &super::PublishedRecord| -> Result<(), DeploymentSessionError> {
        let mut found = published.children.clone();
        found.sort_unstable();
        if published.record != experience_bytes || found != expected_children {
            return Err(invalid(
                "the immutable learning publication differs from its exact source closure",
            ));
        }
        Ok(())
    };
    let (published_root, committed) = if let Some(existing) = existing {
        verify(&existing)?;
        (existing.root, false)
    } else {
        let receipt = publish_record(
            root,
            &slot,
            "agent-learning",
            &experience_bytes,
            &children,
            None,
        )?;
        let verified = read_published(root, &slot)?
            .ok_or_else(|| invalid("the learning root was not visible after publication"))?;
        verify(&verified)?;
        if verified.root != receipt.root {
            return Err(invalid("the learning root changed during publication"));
        }
        (receipt.root, true)
    };
    Ok(PublishedLearning {
        contract_basis: position.workspace.contract_basis().clone(),
        experience: blueprint.experience,
        proposal: blueprint.proposal,
        root: published_root,
        experience_digest,
        proposal_digest,
        episode_root: episode.root,
        feedback_root: feedback.root,
        plan_root,
        committed,
        missing_evidence: blueprint.missing_evidence,
        evidence,
        original_resource_use_json: episode.record.episode.resource_use_json.clone(),
    })
}

mod inspect;
pub use inspect::{InspectLearningRequest, LearningInspection, inspect_learning};

mod inventory;
pub use inventory::MAX_CAPTURED_LEARNING;
pub(super) use inventory::{CapturedLearningInventory, captured_inventory};

mod recovery;
pub(crate) use recovery::{decode_experience, verify_recovery_closure};

#[cfg(test)]
mod tests;
