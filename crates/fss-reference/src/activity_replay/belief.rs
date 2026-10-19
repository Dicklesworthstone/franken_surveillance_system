#![forbid(unsafe_code)]
//! Statically selected native activity derivation for the retained-belief verifier.
//!
//! The engine admits one exact, independently bound invocation. Every source and metadata role
//! must have verified membership in the expected authority revision before any native execution.
//! It replays the pinned activity package from original JPEG bytes; it never copies an offered
//! statement, confidence, score or receipt into a verified answer. This is computation provenance,
//! not physical-world truth, model activation, read permission, presence or absence certification.

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fmt;

use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::belief_verification::{
    BeliefRebuildInputs, RegisteredBeliefDeriver, VerifiedBeliefEvidence,
};
use fss_core::{
    BeliefInterval, CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, DerivedBelief,
    DerivedBeliefParams, DigestAlgorithm, Generation, KnowledgeState, LedgerAnchor, ObjectId,
    ObjectRevision, Plane, ProvenanceClass,
};
use fss_publication::{
    ROOT_REACHABILITY_FAMILY, ROOT_REACHABILITY_OBJECT_PREFIX, SlotName,
    root_reachability_object_id,
};

use super::{
    ActivityReplayError, ActivityReplayInputs, ActivityReplayLimits, ActivityReplayPlan,
    replay_activity_result,
};
use crate::ScalarExecCx;
use crate::executor_activity::{
    ACTIVITY_MODEL_GENERATION, ActivityExecutorModel, ExecutorModelOutcome, ExecutorModelResult,
};

/// Concrete reference algorithm implemented here; no dynamic registry or downloaded plugin.
pub const ACTIVITY_BELIEF_ALGORITHM: &str = "alg:fss-activity-replay:v1";
/// Generation of this exact belief-construction contract, not a production activation.
pub const ACTIVITY_BELIEF_GENERATION: Generation = Generation(1);
/// Domain binding the independently selected semantic invocation and its complete evidence roles.
pub const ACTIVITY_BELIEF_REQUEST_DOMAIN: &str = "fss.activity_belief.request.v1";

/// Expected membership of one exact payload, selected by the verifier rather than by the claim.
///
/// The authority revision describes the published container, NOT the semantic type of the leaf.
/// Native decoders and the replay contract establish the leaf's computational role separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityEvidenceBinding {
    /// Exact role payload digest; repeated roles may share bytes.
    pub digest: ContentDigest,
    /// Current independently authorized local-root object identity.
    pub authority: ObjectId,
    /// Exact expected authority revision, including container root, generation and validity.
    pub revision: ObjectRevision,
}

/// All eight required roles. No role is discovered by scanning an untrusted payload or a store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityEvidenceSet {
    /// Original executor result.
    pub result: ActivityEvidenceBinding,
    /// Original invocation receipt JSON.
    pub invocation: ActivityEvidenceBinding,
    /// Original evaluated JPEG.
    pub frame_source: ActivityEvidenceBinding,
    /// Original reference JPEG.
    pub reference_source: ActivityEvidenceBinding,
    /// Evaluated frame's source capsule.
    pub frame_capsule: ActivityEvidenceBinding,
    /// Earlier frame's source capsule.
    pub reference_capsule: ActivityEvidenceBinding,
    /// Evaluated frame's native decode record.
    pub frame_decode: ActivityEvidenceBinding,
    /// Reference frame's native decode record.
    pub reference_decode: ActivityEvidenceBinding,
}
impl ActivityEvidenceSet {
    fn ordered(&self) -> [&ActivityEvidenceBinding; 8] {
        [
            &self.result,
            &self.invocation,
            &self.frame_source,
            &self.reference_source,
            &self.frame_capsule,
            &self.reference_capsule,
            &self.frame_decode,
            &self.reference_decode,
        ]
    }
    /// Complete supporting-root set, canonical and deduplicated. Equal bytes never invent a role.
    #[must_use]
    pub fn roots(&self) -> Vec<ContentDigest> {
        self.ordered()
            .iter()
            .map(|binding| binding.digest)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Precise engine refusal; the core trait maps engine failures to its existing evidence refusal.
#[derive(Debug)]
pub enum ActivityBeliefError {
    /// The selected semantic plan or authority binding is inconsistent.
    InvalidBinding,
    /// This request-owned engine has already admitted its one native attempt.
    AlreadyAttempted,
    /// The core did not supply the exact complete, scoped evidence set.
    EvidenceRequired,
    /// Native reproduction failed; no successful belief is returned.
    Replay(ActivityReplayError),
    /// Canonical belief construction or package registration failed.
    Contract(ContractError),
}
impl fmt::Display for ActivityBeliefError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinding => {
                f.write_str("invalid activity belief registration or evidence binding")
            }
            Self::AlreadyAttempted => {
                f.write_str("activity belief engine already attempted this request")
            }
            Self::EvidenceRequired => {
                f.write_str("activity belief requires its exact verified evidence roles")
            }
            Self::Replay(error) => write!(f, "activity belief {error}"),
            Self::Contract(error) => write!(f, "activity belief contract: {error}"),
        }
    }
}
impl std::error::Error for ActivityBeliefError {}
impl From<ContractError> for ActivityBeliefError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}

/// One statically registered native invocation under independently selected authority and limits.
///
/// Construction loads only the committed, digest-pinned first-party activity package. The engine
/// is request-owned and permits at most one native attempt, including failures. A retry requires
/// explicit new admission; no stored result, implicit larger budget or cached proof is reused.
/// Decode work is shared across both source frames. Scalar and decode cancellation remain owned by
/// the supplied contexts. The surrounding graph/durable verifier must use the same cancellation
/// condition when admission, filesystem reads or final projection also need to stop.
pub struct ActivityBeliefEngine<'a> {
    model: ActivityExecutorModel,
    plan: ActivityReplayPlan,
    evidence: ActivityEvidenceSet,
    roots: Vec<ContentDigest>,
    belief_id: String,
    limits: ActivityReplayLimits,
    decode: RefCell<DecodeBudget<'a>>,
    cx: &'a ScalarExecCx,
    attempted: Cell<bool>,
    decode_work: Cell<u64>,
}

impl<'a> ActivityBeliefEngine<'a> {
    /// Selects the committed native implementation independently of any offered belief.
    ///
    /// The application must authorize every bound raw source and metadata role first. Local-root
    /// membership alone is not a privacy grant. This profile does not accept arbitrary families or
    /// infer a role from a manifest-shaped byte string. Revisions must agree for a shared authority
    /// identity. Resource ceilings are operational admission, not semantic configuration; the
    /// original scalar execution allowance IS semantic because the receipt encodes it.
    pub fn load_committed(
        plan: ActivityReplayPlan,
        evidence: ActivityEvidenceSet,
        limits: ActivityReplayLimits,
        decode: DecodeBudget<'a>,
        cx: &'a ScalarExecCx,
    ) -> Result<Self, ActivityBeliefError> {
        if plan.job_id.is_empty()
            || plan.job_id.len() > 128
            || !plan.job_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ActivityBeliefError::InvalidBinding);
        }
        let ordered = evidence.ordered();
        for (position, binding) in ordered.iter().enumerate() {
            let sha = |root: ContentDigest| {
                root.algorithm() == DigestAlgorithm::Sha256 && root.bytes() != [0; 32]
            };
            if !sha(binding.digest)
                || !sha(binding.revision.payload_digest)
                || binding.revision.family != ROOT_REACHABILITY_FAMILY
                || binding.revision.plane != Plane::Authority
                || binding.revision.generation != 1
                || binding.revision.validity.earliest > binding.revision.validity.latest
            {
                return Err(ActivityBeliefError::InvalidBinding);
            }
            let slot = binding
                .authority
                .as_str()
                .strip_prefix(ROOT_REACHABILITY_OBJECT_PREFIX)
                .and_then(|name| SlotName::parse(name).ok())
                .ok_or(ActivityBeliefError::InvalidBinding)?;
            if root_reachability_object_id(&slot).ok().as_ref() != Some(&binding.authority)
                || ordered[..position].iter().any(|previous| {
                    previous.authority == binding.authority && previous.revision != binding.revision
                })
            {
                return Err(ActivityBeliefError::InvalidBinding);
            }
        }
        let model = ActivityExecutorModel::load_committed(cx)
            .map_err(|error| ActivityBeliefError::Replay(ActivityReplayError::Activity(error)))?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(ACTIVITY_BELIEF_REQUEST_DOMAIN);
        encoder.text(ACTIVITY_BELIEF_ALGORITHM);
        encoder.u64(ACTIVITY_BELIEF_GENERATION.0);
        encoder.digest(model.digest());
        encoder.text(plan.sensor_id.as_str());
        encoder.text(plan.stream_id.as_str());
        encoder.text(&plan.job_id);
        encoder.digest(plan.policy.digest());
        encoder.u64(plan.policy.generation());
        encoder.u8(match plan.interpretation {
            ComponentInterpretation::Grayscale => 1,
            ComponentInterpretation::YCbCr => 2,
        });
        encoder.u64(plan.execution.max_macs);
        encoder.u64(
            u64::try_from(plan.execution.max_bytes)
                .map_err(|_| ActivityBeliefError::InvalidBinding)?,
        );
        for binding in ordered {
            encoder.digest(binding.digest);
            binding.authority.encode_canonical(&mut encoder);
            binding.revision.encode_canonical(&mut encoder);
        }
        let identity = ContentDigest::sha256(&encoder.finish_checked()?);
        let hex: String = identity
            .bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let roots = evidence.roots();
        Ok(Self {
            model,
            plan,
            evidence,
            roots,
            belief_id: format!("belief:activity-replay:{hex}"),
            limits,
            decode: RefCell::new(decode),
            cx,
            attempted: Cell::new(false),
            decode_work: Cell::new(0),
        })
    }

    /// Proposition identity binds all ordered roles, authority revisions and semantic configuration.
    #[must_use]
    pub fn belief_id(&self) -> &str {
        &self.belief_id
    }
    /// Exact expected supporting set; no contradiction-set interpretation exists in this profile.
    #[must_use]
    pub fn supporting_roots(&self) -> &[ContentDigest] {
        &self.roots
    }
    /// Whether the request's native-attempt admission was consumed, even if replay failed.
    #[must_use]
    pub fn attempted(&self) -> bool {
        self.attempted.get()
    }
    /// Native decoder work consumed by the engine attempt, retained on failure too.
    #[must_use]
    pub fn decode_work_used(&self) -> u64 {
        self.decode_work.get()
    }

    /// Constructs an UNVERIFIED offered belief for a retained result at a supplied anchor.
    ///
    /// This only formats the claim; it performs no custody reads or native replay and returns no
    /// private verified type. Pass the bytes to the graph/durable verifier with this engine. The
    /// uncertainty interval is deliberately [0,1]: a pixel-change score is not a calibrated
    /// probability of presence. Neither quietness nor a successful replay proves absence.
    pub fn offer(
        &self,
        result: &ExecutorModelResult,
        anchor: &LedgerAnchor,
    ) -> Result<DerivedBelief, ContractError> {
        if result.model_generation != ACTIVITY_MODEL_GENERATION
            || result.model_digest != self.model.digest()
            || result.sensor_id != self.plan.sensor_id
            || result.threshold_policy_generation != self.plan.policy.generation()
            || result.threshold_policy_digest != self.plan.policy.digest()
            || result.object_digest() != self.evidence.result.digest
        {
            return Err(ContractError::EvidenceRequired);
        }
        let (class, bits) = match result.outcome {
            ExecutorModelOutcome::Activity { score_bits } => ("activity", score_bits),
            ExecutorModelOutcome::NoActivity { score_bits } => ("no_activity", score_bits),
            ExecutorModelOutcome::Abstained { .. } => return Err(ContractError::EvidenceRequired),
        };
        if !f32::from_bits(bits).is_finite() || f32::from_bits(bits) < 0.0 {
            return Err(ContractError::EvidenceRequired);
        }
        let statement = format!(
            "Native pixel-change computation for {} in {}: {class}; uncalibrated score bits {bits:08x}; reference-only; no presence or absence claim.",
            self.plan.sensor_id, self.plan.stream_id
        );
        DerivedBelief::new(
            DerivedBeliefParams {
                belief_id: self.belief_id.clone(),
                anchor: anchor.clone(),
                generation: ACTIVITY_BELIEF_GENERATION,
                algorithm_id: ACTIVITY_BELIEF_ALGORITHM.to_owned(),
                statement,
                knowledge_state: KnowledgeState::Estimated,
                provenance: ProvenanceClass::Derived,
                uncertainty: BeliefInterval::new(0, 1_000_000)?,
                supporting_evidence: self.roots.clone(),
                contradictions: Vec::new(),
                derivation_receipt: ContentDigest::sha256(b"unsealed"),
            }
            .with_computed_receipt()?,
        )
    }

    fn bytes<'b>(
        input: &'b BeliefRebuildInputs<'_>,
        binding: &ActivityEvidenceBinding,
    ) -> Result<&'b [u8], ActivityBeliefError> {
        let evidence = input
            .supporting
            .iter()
            .find(|source| source.digest() == binding.digest)
            .ok_or(ActivityBeliefError::EvidenceRequired)?;
        if !has_membership(evidence, binding) {
            return Err(ActivityBeliefError::EvidenceRequired);
        }
        Ok(evidence.bytes())
    }

    /// Independently rebuilds from private verified evidence. Used by the core trait below.
    /// Rejects incomplete/extra roots, any contradictions, a different proposition or wrong typed
    /// authority before native execution. The one-attempt allowance is consumed only after all
    /// eight roles have verified membership, so preflight refusal never starts the model.
    pub fn rebuild(
        &self,
        input: &BeliefRebuildInputs<'_>,
    ) -> Result<DerivedBelief, ActivityBeliefError> {
        if input.belief_id != self.belief_id
            || !input.contradicting.is_empty()
            || !input
                .supporting
                .iter()
                .map(VerifiedBeliefEvidence::digest)
                .eq(self.roots.iter().copied())
        {
            return Err(ActivityBeliefError::EvidenceRequired);
        }
        let data = ActivityReplayInputs {
            result: Self::bytes(input, &self.evidence.result)?,
            invocation: Self::bytes(input, &self.evidence.invocation)?,
            frame_source: Self::bytes(input, &self.evidence.frame_source)?,
            reference_source: Self::bytes(input, &self.evidence.reference_source)?,
            frame_capsule: Self::bytes(input, &self.evidence.frame_capsule)?,
            reference_capsule: Self::bytes(input, &self.evidence.reference_capsule)?,
            frame_decode: Self::bytes(input, &self.evidence.frame_decode)?,
            reference_decode: Self::bytes(input, &self.evidence.reference_decode)?,
        };
        if self.attempted.replace(true) {
            return Err(ActivityBeliefError::AlreadyAttempted);
        }
        let mut budget = self
            .decode
            .try_borrow_mut()
            .map_err(|_| ActivityBeliefError::AlreadyAttempted)?;
        let start = budget.used();
        let replay = replay_activity_result(
            &self.model,
            &self.plan,
            data,
            self.limits,
            &mut budget,
            self.cx,
        );
        self.decode_work.set(budget.used() - start);
        let replay = replay.map_err(ActivityBeliefError::Replay)?;
        Ok(self.offer(replay.result(), input.anchor)?)
    }
}

fn has_membership(evidence: &VerifiedBeliefEvidence, expected: &ActivityEvidenceBinding) -> bool {
    evidence.bindings().iter().any(|(id, revision)| {
        id == &expected.authority
            && revision == &expected.revision
            && revision.payload_digest == expected.digest
    }) || evidence.ancestry().iter().any(|path| {
        path.object_id() == &expected.authority
            && path.revision() == &expected.revision
            && path.path().first() == Some(&expected.revision.payload_digest)
            && path.path().last() == Some(&expected.digest)
    })
}

impl RegisteredBeliefDeriver for ActivityBeliefEngine<'_> {
    fn algorithm_id(&self) -> &str {
        ACTIVITY_BELIEF_ALGORITHM
    }
    fn generation(&self) -> Generation {
        ACTIVITY_BELIEF_GENERATION
    }
    fn derive(&self, input: &BeliefRebuildInputs<'_>) -> Result<DerivedBelief, ContractError> {
        self.rebuild(input).map_err(|error| match error {
            ActivityBeliefError::Contract(error) => error,
            _ => ContractError::EvidenceRequired,
        })
    }
}
