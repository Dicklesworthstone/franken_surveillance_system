#![forbid(unsafe_code)]
//! Anonymous household context for an exact event, without identity or alert authority.
//!
//! The context is a bounded set of **operator assertions**. A digest binds those assertions;
//! it does not verify their truth, independence, consent, or source availability. The reference
//! evaluator preserves that distinction even when several declared signals support a familiar
//! activity hypothesis. It never modifies the event, suppresses an alert, or certifies absence.

use std::collections::BTreeSet;

use crate::{
    CanonicalEncoder, ContentDigest, DigestAlgorithm, EventHypothesis, EventId, EventKind,
    EventState, EvidenceEdgeRelation, TimestampNs,
};

mod input;
#[cfg(test)]
mod tests;

/// Versioned, non-durable control input. No input bytes become canonical authority.
pub const CONTEXT_SCHEMA: &str = "fss.event_familiarity_context.v1";
/// Read-only advice schema.
pub const ADVICE_SCHEMA: &str = "fss.event_familiarity_advice.v1";
/// Maximum complete context size; over-bound inputs are refused, never truncated.
pub const MAX_CONTEXT_BYTES: usize = 65_536;
/// Maximum number of asserted signals.
pub const MAX_SIGNALS: usize = 32;
/// Maximum number of shared failure domains per asserted signal.
pub const MAX_DOMAINS: usize = 8;
/// Finite reference-policy lifetime ceiling, not an active retention-policy change.
pub const MAX_SIGNAL_LIFETIME_NS: i128 = 86_400_000_000_000;
/// Appearance is short-lived even under a longer ordinary assertion lifetime.
pub const MAX_APPEARANCE_LIFETIME_NS: i128 = 900_000_000_000;

/// Weak anonymous context families. None establishes a person's identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SignalKind {
    /// A locally authorized door transition, as asserted by the operator.
    AuthorizedDoor,
    /// An anonymous trajectory continuing from an authorized location.
    PathContinuity,
    /// Presence of an explicitly opted-in device; possession is not identity.
    TrustedDevice,
    /// A short-lived, opted-in appearance association tied to an exact model receipt.
    Appearance,
    /// A remembered route or routine, never current physical truth.
    Routine,
    /// An operator's bounded confirmation, never a permanent whitelist.
    OperatorConfirmation,
}
impl SignalKind {
    /// Stable control spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizedDoor => "authorized_door",
            Self::PathContinuity => "path_continuity",
            Self::TrustedDevice => "trusted_device",
            Self::Appearance => "appearance",
            Self::Routine => "routine",
            Self::OperatorConfirmation => "operator_confirmation",
        }
    }
}

/// Supplied coverage information remains an assertion, not a `CoverageWitness`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssertedCoverage {
    /// Operator asserts the interval was covered; no absence claim follows.
    Complete,
    /// Relevant observability is unknown.
    Unknown,
    /// A known gap, outage or other observability limitation remains.
    Degraded,
}
impl AssertedCoverage {
    /// Stable spelling that does not launder an assertion into a certificate.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete_asserted",
            Self::Unknown => "unknown",
            Self::Degraded => "degraded",
        }
    }
}

/// An operator's bounded assessment of a risk, with unknown distinct from clear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssertedRisk {
    /// The operator asserts no such cue; this is not verified absence.
    Clear,
    /// The risk was not assessed or could not be observed.
    Unknown,
    /// A concerning cue is present.
    Present,
}
impl AssertedRisk {
    /// Stable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear_asserted",
            Self::Unknown => "unknown",
            Self::Present => "present",
        }
    }
}

/// A provenance-bearing operator assertion; evidence references are not hydrated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamiliaritySignal {
    /// Exact referenced evidence identity. Duplicate references are refused.
    pub evidence_digest: ContentDigest,
    /// Immutable generation of the source assertion or procedure, not a currentness proof.
    pub source_generation: ContentDigest,
    /// Anonymous signal family.
    pub kind: SignalKind,
    /// Supports familiar activity if true; otherwise preserves a contrary possibility.
    pub supports: bool,
    /// Declared common causes. Overlapping sets are transitively one dependent group.
    pub failure_domains: Vec<String>,
    /// Inclusive start of the assertion's applicability interval.
    pub valid_from_ns: TimestampNs,
    /// Exclusive expiry of its applicability interval.
    pub expires_at_ns: TimestampNs,
    /// Revocation excludes positive support. It cannot erase a contrary possibility.
    pub revoked: bool,
    /// Explicit opt-in assertion; required for device and appearance signals.
    pub opted_in: bool,
    /// Required only for appearance; must name a receipt in the exact native event.
    pub model_receipt: Option<ContentDigest>,
}

/// Complete imported context for one exact event and one current authority snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamiliarityContext {
    /// Exact property namespace; there is no cross-property linkage.
    pub site_lineage: String,
    /// Exact authority root, binding current privacy and other committed generations.
    pub authority_root: ContentDigest,
    /// The local read authority's privacy scope, not a capability grant.
    pub privacy_scope: String,
    /// Stable event identity.
    pub event_id: EventId,
    /// Exact immutable event revision.
    pub event_revision_digest: ContentDigest,
    /// Exact policy generation already named by that event.
    pub event_policy_generation: ContentDigest,
    /// Operator coverage assertion; it never substitutes for a coverage witness.
    pub coverage: AssertedCoverage,
    /// Threat-action cues; clear is only an assertion.
    pub threat_actions: AssertedRisk,
    /// Sensor-integrity cues; clear is only an assertion.
    pub sensor_integrity: AssertedRisk,
    /// A high-consequence concern always prevents a familiar-activity recommendation.
    pub high_consequence: bool,
    /// Complete bounded set of weak signals.
    pub signals: Vec<FamiliaritySignal>,
}

/// Current owner-supplied basis. The evaluator performs no I/O or ambient clock access.
#[derive(Clone, Copy, Debug)]
pub struct FamiliarityBasis<'a> {
    /// Namespace verified by the retained source owner.
    pub site_lineage: &'a str,
    /// Exact authority root verified by the retained source owner.
    pub authority_root: ContentDigest,
    /// Current local read authority's privacy scope.
    pub privacy_scope: &'a str,
    /// Explicit logical evaluation time; callers must label historical evaluation honestly.
    pub at_ns: TimestampNs,
}

/// Typed refusal, with no untrusted input text in diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FamiliarityError {
    /// Invalid schema, count, identity, interval or field.
    Malformed(&'static str),
    /// Context belongs to another site or privacy scope.
    ScopeMismatch,
    /// Context names a different authority root.
    StaleAuthority,
    /// Context names another event revision or policy generation.
    StaleEvent,
    /// Native event validation failed.
    InvalidEvent,
}
impl std::fmt::Display for FamiliarityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "familiarity_context_malformed: {reason}"),
            Self::ScopeMismatch => f.write_str("familiarity_scope_mismatch"),
            Self::StaleAuthority => f.write_str("familiarity_authority_stale"),
            Self::StaleEvent => f.write_str("familiarity_event_stale"),
            Self::InvalidEvent => f.write_str("familiarity_native_event_invalid"),
        }
    }
}
impl std::error::Error for FamiliarityError {}

/// Why an individual positive signal can or cannot contribute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalValidity {
    /// Applicable asserted support, still unverified.
    Applicable,
    /// Positive assertion explicitly revoked.
    Revoked,
    /// Applicability starts after the evaluation time.
    NotYetValid,
    /// Applicability has expired at the evaluation time.
    Expired,
    /// Applicability does not cover the complete uncertain event interval.
    OutsideEvent,
    /// Device or appearance opt-in is absent.
    OptInRequired,
    /// Appearance receipt is not part of the exact retained event.
    ModelMismatch,
}
impl SignalValidity {
    /// Stable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applicable => "applicable_assertion",
            Self::Revoked => "revoked",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::OutsideEvent => "outside_event_interval",
            Self::OptInRequired => "opt_in_required",
            Self::ModelMismatch => "model_receipt_mismatch",
        }
    }
}

/// Retained evaluation of one signal, in canonical evidence-digest order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssessedSignal {
    /// Exact original assertion, with domains sorted.
    pub signal: FamiliaritySignal,
    /// Why the assertion can or cannot contribute positive support.
    pub validity: SignalValidity,
    /// The referenced digest is also present in the native event; this alone verifies no claim.
    pub referenced_by_event: bool,
}

/// Advisory disposition, deliberately distinct from event state and policy outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FamiliarityDisposition {
    /// Several declared weak signals support a possible familiar activity explanation.
    PossibleFamiliarActivity,
    /// Required evidence diversity, applicability or knowledge is missing.
    InsufficientContext,
    /// Contradictions or sensor-integrity concerns remain protected.
    Conflicted,
    /// Degraded observability prevents a familiar-activity conclusion.
    Blocked,
    /// Threat/high-consequence evidence overrides any familiar signals.
    ThreatOverride,
}
impl FamiliarityDisposition {
    /// Stable spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PossibleFamiliarActivity => "possible_familiar_activity",
            Self::InsufficientContext => "insufficient_context",
            Self::Conflicted => "conflicted",
            Self::Blocked => "blocked",
            Self::ThreatOverride => "threat_override",
        }
    }
}

/// Complete deterministic advice. It grants no authority and makes no identity/absence claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FamiliarityAssessment {
    /// Advisory context classification, never the canonical event disposition.
    pub disposition: FamiliarityDisposition,
    /// Canonical semantic identity of the supplied context, independent of input order.
    pub context_digest: ContentDigest,
    /// Exact reference evaluator generation and constants.
    pub advisory_policy_digest: ContentDigest,
    /// Whole decision identity, including the native event and evaluation time.
    pub decision_digest: ContentDigest,
    /// Complete signal inventory, including every expired/revoked/mismatched assertion.
    pub signals: Vec<AssessedSignal>,
    /// Number of declared connected support groups; independence is not verified.
    pub declared_support_groups: usize,
    /// Distinct applicable signal kinds in stable order.
    pub support_kinds: Vec<SignalKind>,
    /// Stable blocking reasons, never user-provided prose.
    pub blockers: Vec<&'static str>,
    /// Stable unresolved facts, preserved even for a possible familiar-activity hypothesis.
    pub unknowns: Vec<&'static str>,
    /// Earliest expiry among applicable positive signals; no indefinite recommendation.
    pub valid_until_ns: Option<TimestampNs>,
}

fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32]
}
fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

impl FamiliarityContext {
    /// Validate the complete input before allocating an assessment or interpreting support.
    pub fn validate(&self) -> Result<(), FamiliarityError> {
        let invalid = FamiliarityError::Malformed;
        if !valid_name(&self.site_lineage)
            || !valid_name(&self.privacy_scope)
            || !valid_name(self.event_id.as_str())
        {
            return Err(invalid("scope identity"));
        }
        if ![
            self.authority_root,
            self.event_revision_digest,
            self.event_policy_generation,
        ]
        .into_iter()
        .all(valid_digest)
        {
            return Err(invalid("basis digest"));
        }
        if self.signals.len() > MAX_SIGNALS {
            return Err(invalid("signal count"));
        }
        let mut evidence = BTreeSet::new();
        for signal in &self.signals {
            if !valid_digest(signal.evidence_digest)
                || !valid_digest(signal.source_generation)
                || !evidence.insert(signal.evidence_digest)
            {
                return Err(invalid("signal digest or duplicate evidence"));
            }
            if signal.failure_domains.is_empty() || signal.failure_domains.len() > MAX_DOMAINS {
                return Err(invalid("failure domain count"));
            }
            let mut domains = BTreeSet::new();
            for domain in &signal.failure_domains {
                if !valid_name(domain) || !domains.insert(domain) {
                    return Err(invalid("failure domain identity or duplicate"));
                }
            }
            let limit = if signal.kind == SignalKind::Appearance {
                MAX_APPEARANCE_LIFETIME_NS
            } else {
                MAX_SIGNAL_LIFETIME_NS
            };
            if !signal
                .expires_at_ns
                .0
                .checked_sub(signal.valid_from_ns.0)
                .is_some_and(|span| span > 0 && span <= limit)
            {
                return Err(invalid("signal lifetime"));
            }
            match (signal.kind, signal.model_receipt) {
                (SignalKind::Appearance, Some(receipt)) if valid_digest(receipt) => {}
                (SignalKind::Appearance, _) => return Err(invalid("appearance model receipt")),
                (_, None) => {}
                (_, Some(_)) => return Err(invalid("model receipt on non-appearance signal")),
            }
        }
        Ok(())
    }

    /// Semantic fingerprint uses hand-written bounded canonical encoding, never JSON layout.
    pub fn digest(&self) -> Result<ContentDigest, FamiliarityError> {
        self.validate()?;
        let mut encoder = CanonicalEncoder::new();
        encoder.text(CONTEXT_SCHEMA);
        encoder.text(&self.site_lineage);
        encoder.digest(self.authority_root);
        encoder.text(&self.privacy_scope);
        encoder.text(self.event_id.as_str());
        encoder.digest(self.event_revision_digest);
        encoder.digest(self.event_policy_generation);
        encoder.text(self.coverage.as_str());
        encoder.text(self.threat_actions.as_str());
        encoder.text(self.sensor_integrity.as_str());
        encoder.bool(self.high_consequence);
        let mut signals: Vec<_> = self.signals.iter().collect();
        signals.sort_by_key(|signal| signal.evidence_digest);
        encoder.u64(signals.len() as u64);
        for signal in signals {
            encoder.digest(signal.evidence_digest);
            encoder.digest(signal.source_generation);
            encoder.text(signal.kind.as_str());
            encoder.bool(signal.supports);
            let domains: BTreeSet<_> = signal.failure_domains.iter().collect();
            encoder.u64(domains.len() as u64);
            for domain in domains {
                encoder.text(domain);
            }
            encoder.i128(signal.valid_from_ns.0);
            encoder.i128(signal.expires_at_ns.0);
            encoder.bool(signal.revoked);
            encoder.bool(signal.opted_in);
            encoder.bool(signal.model_receipt.is_some());
            if let Some(receipt) = signal.model_receipt {
                encoder.digest(receipt);
            }
        }
        let bytes = encoder
            .finish_checked()
            .map_err(|_| FamiliarityError::Malformed("canonical bound"))?;
        Ok(ContentDigest::sha256(&bytes))
    }
}

fn validity(
    signal: &FamiliaritySignal,
    event: &EventHypothesis,
    at: TimestampNs,
) -> SignalValidity {
    if signal.revoked {
        return SignalValidity::Revoked;
    }
    if matches!(
        signal.kind,
        SignalKind::TrustedDevice | SignalKind::Appearance
    ) && !signal.opted_in
    {
        return SignalValidity::OptInRequired;
    }
    if at < signal.valid_from_ns {
        return SignalValidity::NotYetValid;
    }
    if at >= signal.expires_at_ns {
        return SignalValidity::Expired;
    }
    if signal.valid_from_ns > event.interval.earliest
        || signal.expires_at_ns <= event.interval.latest
    {
        return SignalValidity::OutsideEvent;
    }
    if signal.kind == SignalKind::Appearance
        && !signal
            .model_receipt
            .is_some_and(|receipt| event.model_receipts.contains(&receipt))
    {
        return SignalValidity::ModelMismatch;
    }
    SignalValidity::Applicable
}

/// Evaluate declared familiarity at one exact native event, snapshot and explicit time.
/// Work and allocations are bounded by the signal/domain limits. Every contrary signal
/// remains a protected possibility, even if it expires or its positive authority is revoked.
pub fn assess_familiarity(
    event: &EventHypothesis,
    context: &FamiliarityContext,
    basis: FamiliarityBasis<'_>,
) -> Result<FamiliarityAssessment, FamiliarityError> {
    context.validate()?;
    event
        .validate()
        .map_err(|_| FamiliarityError::InvalidEvent)?;
    if context.site_lineage != basis.site_lineage || context.privacy_scope != basis.privacy_scope {
        return Err(FamiliarityError::ScopeMismatch);
    }
    if context.authority_root != basis.authority_root {
        return Err(FamiliarityError::StaleAuthority);
    }
    if context.event_id != event.event_id
        || context.event_revision_digest != event.revision_digest()
        || context.event_policy_generation != event.decision_path.policy_generation
    {
        return Err(FamiliarityError::StaleEvent);
    }
    if basis.at_ns < event.interval.latest {
        return Err(FamiliarityError::Malformed(
            "evaluation precedes event interval",
        ));
    }
    let mut signals: Vec<_> = context
        .signals
        .iter()
        .map(|signal| {
            let mut signal = signal.clone();
            signal.failure_domains.sort();
            AssessedSignal {
                validity: validity(&signal, event, basis.at_ns),
                referenced_by_event: event
                    .evidence
                    .iter()
                    .any(|edge| edge.digest == signal.evidence_digest),
                signal,
            }
        })
        .collect();
    signals.sort_by_key(|row| row.signal.evidence_digest);
    let supporting: Vec<_> = signals
        .iter()
        .filter(|row| row.signal.supports && row.validity == SignalValidity::Applicable)
        .collect();
    let support_kinds: Vec<_> = supporting
        .iter()
        .map(|row| row.signal.kind)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // Merge common causes transitively. Pairwise-distinct names are not enough when a third
    // signal bridges two groups. Full recomputation is tiny and deterministic at this bound.
    let mut groups: Vec<(BTreeSet<&str>, bool)> = Vec::new();
    for row in &signals {
        let mut domains: BTreeSet<_> = row
            .signal
            .failure_domains
            .iter()
            .map(String::as_str)
            .collect();
        let mut supports = row.signal.supports && row.validity == SignalValidity::Applicable;
        let mut index = 0;
        while index < groups.len() {
            if !domains.is_disjoint(&groups[index].0) {
                let (shared, active) = groups.remove(index);
                domains.extend(shared);
                supports |= active;
                index = 0;
            } else {
                index += 1;
            }
        }
        groups.push((domains, supports));
    }
    let declared_support_groups = groups.iter().filter(|(_, supports)| *supports).count();
    let mut blockers = BTreeSet::new();
    let mut unknowns = BTreeSet::from([
        "context_assertions_unverified",
        "coverage_not_certified",
        "identity_unresolved",
        "source_independence_unverified",
    ]);
    if context.high_consequence
        || context.threat_actions == AssertedRisk::Present
        || matches!(
            event.kind,
            EventKind::PerimeterBreach | EventKind::CovertApproach | EventKind::SensorTamper
        )
    {
        blockers.insert("threat_or_high_consequence_evidence");
    }
    if context.sensor_integrity == AssertedRisk::Present
        || event
            .evidence
            .iter()
            .any(|edge| edge.reports_sensor_tamper())
    {
        blockers.insert("sensor_integrity_concern");
    }
    if context.signals.iter().any(|signal| !signal.supports)
        || event.evidence.iter().any(|edge| {
            matches!(
                edge.relation,
                EvidenceEdgeRelation::Contradicts | EvidenceEdgeRelation::Invalidates
            )
        })
    {
        blockers.insert("unresolved_contradiction");
    }
    if context.coverage == AssertedCoverage::Degraded {
        blockers.insert("coverage_degraded");
    }
    if context.coverage == AssertedCoverage::Unknown {
        unknowns.insert("coverage_unknown");
    }
    if context.threat_actions == AssertedRisk::Unknown {
        unknowns.insert("threat_actions_unknown");
    }
    if context.sensor_integrity == AssertedRisk::Unknown {
        unknowns.insert("sensor_integrity_unknown");
    }
    if matches!(
        event.state,
        EventState::Hypothesized | EventState::Indeterminate
    ) {
        unknowns.insert("canonical_event_unresolved");
    }
    let guards_asserted = context.coverage == AssertedCoverage::Complete
        && context.threat_actions == AssertedRisk::Clear
        && context.sensor_integrity == AssertedRisk::Clear;
    let continuity = support_kinds.iter().any(|kind| {
        matches!(
            kind,
            SignalKind::AuthorizedDoor | SignalKind::PathContinuity
        )
    });
    let disposition = if blockers.contains("threat_or_high_consequence_evidence") {
        FamiliarityDisposition::ThreatOverride
    } else if blockers.contains("unresolved_contradiction")
        || blockers.contains("sensor_integrity_concern")
    {
        FamiliarityDisposition::Conflicted
    } else if blockers.contains("coverage_degraded") {
        FamiliarityDisposition::Blocked
    } else if guards_asserted
        && continuity
        && support_kinds.len() >= 2
        && declared_support_groups >= 2
    {
        FamiliarityDisposition::PossibleFamiliarActivity
    } else {
        FamiliarityDisposition::InsufficientContext
    };
    let context_digest = context.digest()?;
    let advisory_policy_digest = ContentDigest::sha256(b"fss.familiarity.reference.v1;assertions-only;signals=32;domains=8;ttl=86400000000000;appearance=900000000000;distinct-kinds=2;declared-groups=2;continuity-required;threat-veto;contradictions-protected;no-identity-or-alert-suppression");
    let valid_until_ns = supporting.iter().map(|row| row.signal.expires_at_ns).min();
    let mut encoder = CanonicalEncoder::new();
    encoder.text(ADVICE_SCHEMA);
    encoder.digest(context_digest);
    encoder.digest(advisory_policy_digest);
    encoder.i128(basis.at_ns.0);
    encoder.text(disposition.as_str());
    encoder.u64(declared_support_groups as u64);
    for row in &signals {
        encoder.digest(row.signal.evidence_digest);
        encoder.text(row.validity.as_str());
        encoder.bool(row.referenced_by_event);
    }
    encoder.u64(blockers.len() as u64);
    for reason in &blockers {
        encoder.text(reason);
    }
    encoder.u64(unknowns.len() as u64);
    for reason in &unknowns {
        encoder.text(reason);
    }
    let decision_digest = ContentDigest::sha256(
        &encoder
            .finish_checked()
            .map_err(|_| FamiliarityError::Malformed("advice bound"))?,
    );
    Ok(FamiliarityAssessment {
        disposition,
        context_digest,
        advisory_policy_digest,
        decision_digest,
        signals,
        declared_support_groups,
        support_kinds,
        blockers: blockers.into_iter().collect(),
        unknowns: unknowns.into_iter().collect(),
        valid_until_ns,
    })
}
