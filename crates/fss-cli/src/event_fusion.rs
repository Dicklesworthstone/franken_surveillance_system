#![forbid(unsafe_code)]
//! Calibrated class advice over native watch/corroboration results (fss-808pm).
//!
//! This adapter consumes the actual source-linked cascade, not a JSON score supplied by a
//! caller. Calibration is an explicit, exact-plan owner assertion, not deployment activation.
//! The existing fusion crate alone owns probability arithmetic, common causes and decisions.
//! Candidate-selected frames do not certify class absence. Advice never changes event kind,
//! event publication approval, coverage authority, or the alert/effect state machine.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::{CanonicalEncode, CanonicalEncoder, ContentDigest, LedgerAnchor, SensorId};
use fss_fusion::{
    Calibration, Coverage, EvidenceItem, FusionOutcome, FusionPolicy, FusionQuery, LlrInterval,
    Observability, ScoreCalibration, Severity, fuse,
};
use fss_reference::ingest::detector_cascade::{ClassEvidence, DetectorCascade, EvidenceOutcome};
use fss_reference::ingest::recorded_corroboration::CorroborationReport;
use fss_reference::ingest::recorded_watch::WatchReport;
use fss_reference::{ReferenceDeployment, ReplayCx};

mod corroboration;
mod guarded;
mod input;
mod render;
mod streaming;
pub use corroboration::MAX_LONG_CORROBORATION_CANDIDATES;
pub use input::MAX_PROFILE_BYTES;
pub use streaming::MAX_LONG_CANDIDATES;

/// Maximum short-window advice records. Whole-recording watch uses MAX_LONG_CANDIDATES;
/// either adapter refuses excess work instead of returning a successful prefix.
pub const MAX_CANDIDATES: usize = 32;
/// One shared evidence-processing allowance across every candidate, including omissions.
pub const MAX_TOTAL_EVIDENCE: usize = 256;
/// Complete JSON output ceiling; checked before caller-side publication.
pub const MAX_REPORT_BYTES: usize = 2 * 1024 * 1024;
/// Interpretation of source binding and score quantization, not a calibration certificate.
pub const RECIPE: &str =
    "fss.event_class_fusion.v1:exact-plan:score-ppm-outward-hull:no-absence:no-effects";

/// Explicit calibration applicability assertion for one retained sensor in the exact plan.
#[derive(Clone, Debug)]
pub struct SensorCalibration {
    /// Native retained sensor identity, not a command-line camera alias.
    pub sensor: String,
    /// Labelled-count calibration; every derived field is independently rebuilt and checked.
    pub calibration: ScoreCalibration,
    /// Additional possible common causes; these can only contract independence.
    pub failure_domains: BTreeSet<String>,
}

/// Explicit immutable analysis request. No value is inferred from wall time or detector scores.
#[derive(Clone, Debug)]
pub struct ClassFusionSpec {
    /// Exact final native analysis identity. Whole-recording modes pin their analysis digest,
    /// not the smaller input plan; this includes the complete scan and trained-stage outcome.
    pub plan_digest: ContentDigest,
    /// Exact native coverage records for short-window analysis. Whole-recording profiles must
    /// leave this empty and bind their roots through the matching whole-recording constructor.
    /// Neither form certifies detector-class absence.
    pub coverage_digests: BTreeSet<ContentDigest>,
    /// Exact native cascade. Whole-recording modes use their complete retained detector-recipe
    /// digest, including package, execution, selection and whole-recording resource ceilings.
    pub cascade_digest: ContentDigest,
    /// Vocabulary index in the verified native package. The hypothesis is only this class.
    pub class_index: usize,
    /// Explicit prior; evaluation-population prevalence is never silently a deployment prior.
    pub prior: LlrInterval,
    /// Versioned owner-selected decision policy; not activated by this read-only request.
    pub policy: FusionPolicy,
    /// Explicit consequence assumptions, orthogonal to probability.
    pub severity: Severity,
    /// Owner-declared number of looks. This adapter does not maintain a persistent look counter.
    pub looks: u32,
    /// Owner-declared evidence-clock time; no arrival time becomes capture time.
    pub now_ns: u64,
    /// At most eight unique sensors. Missing bindings remain explicitly uncalibrated.
    pub calibrations: Vec<SensorCalibration>,
}

/// Payload-free adapter refusal; no source, path, label or credential bytes are printed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventFusionError {
    /// Invalid bounds, policy, identities or calibration counts/digest.
    Profile,
    /// Profile does not bind this exact native source/pipeline, or names a foreign sensor.
    Scope,
    /// Native source basis is no longer the current authority anchor.
    StaleBasis,
    /// Source evidence or numeric score is inconsistent.
    Evidence,
    /// Whole-report candidate, evidence, encoding or output capacity exhausted.
    Limit,
    /// Explicit owner cancellation.
    Cancelled,
}
impl EventFusionError {
    /// Stable operator diagnostic identity.
    pub fn stable_id(self) -> &'static str {
        match self {
            Self::Profile => "ERR-EVENT-FUSION-PROFILE-001",
            Self::Scope => "ERR-EVENT-FUSION-SCOPE-001",
            Self::StaleBasis => "ERR-EVENT-FUSION-STALE-001",
            Self::Evidence => "ERR-EVENT-FUSION-EVIDENCE-001",
            Self::Limit => "ERR-EVENT-FUSION-LIMIT-001",
            Self::Cancelled => "ERR-EVENT-FUSION-CANCELLED-001",
        }
    }
}
impl fmt::Display for EventFusionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_id())
    }
}
impl std::error::Error for EventFusionError {}
type Result<T> = std::result::Result<T, EventFusionError>;

/// Source context for a complete recording analysis, never a coverage witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WholeRecordingScope {
    Watch(ContentDigest),
    Corroboration([ContentDigest; 2]),
}
impl WholeRecordingScope {
    fn roots(&self) -> &[ContentDigest] {
        match self {
            Self::Watch(root) => std::slice::from_ref(root),
            Self::Corroboration(roots) => roots,
        }
    }
}

/// Validated, privately held request. Mutable public calibration structs cannot alter it.
#[derive(Clone, Debug)]
pub struct EventFusionProfile {
    spec: ClassFusionSpec,
    digest: ContentDigest,
    // A source-closed analysis root is NOT a coverage witness. The discriminator is private
    // and included in the semantic digest; short-window entry points refuse this profile.
    whole_recording: Option<WholeRecordingScope>,
}
impl EventFusionProfile {
    /// Validate everything, including all reconstructed calibration fields, before native work.
    pub fn new(spec: ClassFusionSpec) -> Result<Self> {
        Self::new_scoped(spec, None)
    }

    fn new_scoped(
        mut spec: ClassFusionSpec,
        whole_recording: Option<WholeRecordingScope>,
    ) -> Result<Self> {
        if spec.calibrations.is_empty() || spec.calibrations.len() > 8 || spec.class_index > 65_535
        {
            return Err(EventFusionError::Profile);
        }
        match whole_recording {
            Some(scope) => {
                if !spec.coverage_digests.is_empty()
                    || scope.roots().iter().any(|root| {
                        root.algorithm() != fss_core::DigestAlgorithm::Sha256
                            || root.bytes() == [0; 32]
                    })
                {
                    return Err(EventFusionError::Profile);
                }
            }
            None if spec.coverage_digests.is_empty() || spec.coverage_digests.len() > 8 => {
                return Err(EventFusionError::Profile);
            }
            None => {}
        }
        // Validate through the owner of the policy semantics, even for zero-candidate runs.
        let template = query(&spec, "profile", Vec::new());
        fuse(&template).map_err(|_| EventFusionError::Profile)?;
        spec.calibrations.sort_by(|a, b| a.sensor.cmp(&b.sensor));
        let mut generations = BTreeMap::new();
        let mut previous = None;
        let mut e = CanonicalEncoder::new();
        e.text(RECIPE);
        e.digest(spec.plan_digest);
        e.digest(spec.cascade_digest);
        e.u64(spec.coverage_digests.len() as u64);
        for digest in &spec.coverage_digests {
            e.digest(*digest);
        }
        e.u64(spec.class_index as u64);
        e.digest(template.digest());
        e.u64(spec.calibrations.len() as u64);
        for binding in &spec.calibrations {
            if SensorId::parse(&binding.sensor).is_err()
                || previous == Some(binding.sensor.as_str())
                || binding.failure_domains.len() > 8
                || binding
                    .failure_domains
                    .iter()
                    .any(|d| d.is_empty() || d.len() > 192 || d.chars().any(char::is_control))
                || binding.calibration.bins.len() > fss_fusion::calibration::MAX_BINS
                || binding.calibration.generation.len() > 128
            {
                return Err(EventFusionError::Profile);
            }
            previous = Some(binding.sensor.as_str());
            let c = &binding.calibration;
            let edges: Vec<_> = c.bins.iter().map(|b| b.lo_ppm).collect();
            let counts: Vec<_> = c.bins.iter().map(|b| (b.positives, b.negatives)).collect();
            let rebuilt = ScoreCalibration::from_counts(&c.generation, &edges, &counts)
                .map_err(|_| EventFusionError::Profile)?;
            if &rebuilt != c {
                return Err(EventFusionError::Profile);
            }
            if generations
                .insert(c.generation.clone(), c.digest)
                .is_some_and(|old| old != c.digest)
            {
                return Err(EventFusionError::Profile);
            }
            e.text(&binding.sensor);
            e.digest(c.digest);
            e.u64(binding.failure_domains.len() as u64);
            for domain in &binding.failure_domains {
                e.text(domain);
            }
        }
        match whole_recording {
            Some(WholeRecordingScope::Watch(root)) => {
                // Preserve the complete established version-two identity sequence.
                e.text(streaming::SCOPE);
                e.digest(root);
                e.u64(streaming::MAX_LONG_CANDIDATES as u64);
                e.u64(MAX_TOTAL_EVIDENCE as u64);
            }
            Some(WholeRecordingScope::Corroboration(roots)) => {
                e.text(corroboration::SCOPE);
                for root in roots {
                    e.digest(root);
                }
                e.u64(MAX_LONG_CORROBORATION_CANDIDATES as u64);
                e.u64(MAX_TOTAL_EVIDENCE as u64);
            }
            None => {}
        }
        Ok(Self {
            spec,
            digest: digest(e)?,
            whole_recording,
        })
    }
    /// Canonical identity, independent of profile JSON formatting and binding order.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Read-only validated request; calibration mutations require constructing a new profile.
    pub fn spec(&self) -> &ClassFusionSpec {
        &self.spec
    }
}

/// The exact native record and outward score-to-bin conversion used for one fusion input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScoreLink {
    /// Query input identity; synthetic missing-input identities are explicitly separate.
    pub evidence_id: String,
    /// Original retained sensor.
    pub sensor: String,
    /// Source-linked class record; absent only for an explicitly missing observation.
    pub source_record: Option<ContentDigest>,
    /// Original F32 bits, absent when the requested class was not observed.
    pub score_bits: Option<u32>,
    /// Floor/ceiling in ppm. A boundary straddle uses the hull of BOTH calibrated bins.
    pub score_ppm: Option<[u32; 2]>,
    /// Exact selected count-calibration identity; absent when the input was not calibrated.
    pub calibration: Option<ContentDigest>,
}

/// One complete recomputable fusion result, separately bound to its native event proposal.
#[derive(Clone, Debug)]
pub struct CandidateFusion {
    /// Original candidate; not replaced by the class hypothesis.
    pub candidate: ContentDigest,
    /// Original event-approval digest. Fusion is not included in or authorized by this approval.
    pub native_proposal: ContentDigest,
    /// Original source/provenance graph to retain under the native publication protocol.
    pub native_provenance: ContentDigest,
    /// Complete input to the unchanged fusion engine.
    pub query: FusionQuery,
    /// Full exact result, including exclusions, common-cause hulls and counterfactuals.
    pub outcome: FusionOutcome,
    /// Exact score inputs in query identity order, including uncalibrated/missing rows.
    pub scores: Vec<ScoreLink>,
    /// Profile, source context, native proposal, exact scores and complete decision binding.
    pub binding_digest: ContentDigest,
}

/// Complete read-only analysis, never a publication receipt or effect grant.
#[derive(Clone, Debug)]
pub struct EventFusionReport {
    profile: EventFusionProfile,
    basis: LedgerAnchor,
    context: ContentDigest,
    package: ContentDigest,
    label: String,
    results: Vec<CandidateFusion>,
    digest: ContentDigest,
}
impl EventFusionReport {
    /// Fuse native single-camera candidates. An uncalibrated model-free run cannot enter here.
    pub fn watch(
        native: &WatchReport,
        cascade: &DetectorCascade<'_>,
        profile: &EventFusionProfile,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if native.cascade_digest() != Some(cascade.digest()) {
            return Err(EventFusionError::Scope);
        }
        native
            .revalidate_derived_source(deployment, cx)
            .map_err(|_| EventFusionError::Evidence)?;
        let coverage = native.coverage();
        let inputs: Vec<_> = native
            .candidates()
            .iter()
            .map(|c| Input {
                candidate: c.identity(),
                proposal: c.proposal_digest(),
                provenance: c.provenance_root(),
                sources: vec![Source {
                    sensor: &coverage.sensor_id,
                    dependency: None,
                    evidence: &c.class_evidence,
                }],
            })
            .collect();
        let result = Self::analyze(
            native.plan_digest(),
            &[coverage],
            cascade,
            profile,
            inputs,
            deployment,
            cx,
        )?;
        native
            .revalidate_derived_source(deployment, cx)
            .map_err(|_| EventFusionError::Evidence)?;
        checkpoint(cx)?;
        Ok(result)
    }

    /// Fuse only actually associated native camera entries, preserving their dependency domains.
    /// Site-calibrated cameras require `corroborate_guarded` and their final screened records.
    pub fn corroborate(
        native: &CorroborationReport,
        cascade: &DetectorCascade<'_>,
        profile: &EventFusionProfile,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::corroborate_with_coverage(native, cascade, profile, None, deployment, cx)
    }

    fn analyze(
        plan: ContentDigest,
        coverage: &[&fss_reference::ingest::recorded_coverage::CoverageRecord],
        cascade: &DetectorCascade<'_>,
        profile: &EventFusionProfile,
        inputs: Vec<Input<'_>>,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if profile.whole_recording.is_some()
            || plan != profile.spec.plan_digest
            || cascade.digest() != profile.spec.cascade_digest
        {
            return Err(EventFusionError::Scope);
        }
        let basis = deployment.current_anchor().clone();
        if coverage.is_empty() || coverage.iter().any(|c| c.basis != basis) {
            return Err(EventFusionError::StaleBasis);
        }
        let actual: BTreeSet<_> = coverage.iter().map(|c| c.digest()).collect();
        if actual.len() != coverage.len() || actual != profile.spec.coverage_digests {
            return Err(EventFusionError::Scope);
        }
        let sensors: BTreeSet<_> = coverage.iter().map(|c| c.sensor_id.as_str()).collect();
        if profile
            .spec
            .calibrations
            .iter()
            .any(|c| !sensors.contains(c.sensor.as_str()))
        {
            return Err(EventFusionError::Scope);
        }
        let package = cascade.package();
        let label = package
            .spec()
            .labels
            .get(profile.spec.class_index)
            .ok_or(EventFusionError::Scope)?
            .clone();
        if label.len() > 192 || label.chars().any(char::is_control) {
            return Err(EventFusionError::Scope);
        }
        let count = inputs
            .iter()
            .flat_map(|i| &i.sources)
            .try_fold(0usize, |n, s| n.checked_add(s.evidence.len().max(1)))
            .ok_or(EventFusionError::Limit)?;
        if inputs.len() > MAX_CANDIDATES || count > MAX_TOTAL_EVIDENCE {
            return Err(EventFusionError::Limit);
        }
        let mut context = CanonicalEncoder::new();
        context.text(RECIPE);
        context.digest(profile.digest);
        context.digest(plan);
        basis.encode_canonical(&mut context);
        for c in coverage {
            context.digest(c.digest());
        }
        let context = digest(context)?;
        let model_domain = format!(
            "model:{}",
            ContentDigest::sha256(package.manifest().model_id().as_str().as_bytes())
        );
        let package_domain = format!("package:{}", package.archive_digest());
        let pipeline_domain = format!("cascade:{}", cascade.digest());
        let shared = [model_domain, package_domain, pipeline_domain];
        let mut results = Vec::new();
        for input in inputs {
            checkpoint(cx)?;
            results.push(fuse_input(input, &label, profile, context, &shared)?);
        }
        results.sort_by_key(|r| r.candidate);
        let mut e = CanonicalEncoder::new();
        e.text("fss.event_class_fusion.report.v1");
        e.digest(context);
        e.u64(results.len() as u64);
        for r in &results {
            e.digest(r.binding_digest);
        }
        checkpoint(cx)?;
        if deployment.current_anchor() != &basis {
            return Err(EventFusionError::StaleBasis);
        }
        let output = Self {
            profile: profile.clone(),
            basis,
            context,
            package: package.archive_digest(),
            label,
            results,
            digest: digest(e)?,
        };
        // Price complete encoding before callers are able to publish a native event.
        output.to_json()?;
        Ok(output)
    }
    /// One result for every native candidate, in candidate identity order.
    pub fn candidates(&self) -> &[CandidateFusion] {
        &self.results
    }
    /// Exact complete report identity.
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Analysis authority anchor, which may precede a subsequent explicit native publication.
    pub fn basis(&self) -> &LedgerAnchor {
        &self.basis
    }
    /// Complete bounded JSON, with raw engine queries and all counterfactuals for replay.
    pub fn to_json(&self) -> Result<String> {
        let json = render::report(self);
        if json.len() > MAX_REPORT_BYTES {
            return Err(EventFusionError::Limit);
        }
        Ok(json)
    }
}

struct Source<'a> {
    sensor: &'a str,
    dependency: Option<&'a str>,
    evidence: &'a [ClassEvidence],
}
struct Input<'a> {
    candidate: ContentDigest,
    proposal: ContentDigest,
    provenance: ContentDigest,
    sources: Vec<Source<'a>>,
}
fn checkpoint(cx: &ReplayCx) -> Result<()> {
    cx.checkpoint("event_fusion:analysis")
        .map_err(|_| EventFusionError::Cancelled)
}
fn digest(e: CanonicalEncoder) -> Result<ContentDigest> {
    Ok(ContentDigest::sha256(
        &e.finish_checked().map_err(|_| EventFusionError::Limit)?,
    ))
}
fn query(spec: &ClassFusionSpec, hypothesis: &str, evidence: Vec<EvidenceItem>) -> FusionQuery {
    FusionQuery {
        hypothesis: hypothesis.to_owned(),
        kind: "associated_detector_class".to_owned(),
        prior: spec.prior,
        evidence,
        coverage: Coverage::Gap {
            reason: "candidate-selected frames do not certify detector-class absence".to_owned(),
        },
        opportunities: Vec::new(),
        probes: Vec::new(),
        severity: spec.severity,
        policy: spec.policy.clone(),
        looks: spec.looks,
        now_ns: spec.now_ns,
    }
}

fn fuse_input(
    input: Input<'_>,
    label: &str,
    profile: &EventFusionProfile,
    context: ContentDigest,
    shared: &[String],
) -> Result<CandidateFusion> {
    let mut rows = BTreeMap::new();
    for source in &input.sources {
        let binding = profile
            .spec
            .calibrations
            .iter()
            .find(|c| c.sensor == source.sensor);
        let mut domains: BTreeSet<_> = shared.iter().cloned().collect();
        if let Some(dependency) = source.dependency {
            domains.insert(format!(
                "native:{}",
                ContentDigest::sha256(dependency.as_bytes())
            ));
        }
        if let Some(b) = binding {
            domains.extend(b.failure_domains.iter().cloned());
            domains.insert(format!("calibration:{}", b.calibration.digest));
        }
        if source.evidence.is_empty() {
            let id = format!("unobserved:{}", source.sensor);
            let link = ScoreLink {
                evidence_id: id.clone(),
                sensor: source.sensor.to_owned(),
                source_record: None,
                score_bits: None,
                score_ppm: None,
                calibration: None,
            };
            rows.insert(
                id.clone(),
                (
                    EvidenceItem {
                        id,
                        sensor: source.sensor.to_owned(),
                        failure_domains: domains,
                        calibration: Calibration::Uncalibrated {
                            reason: "no selected class observation".to_owned(),
                        },
                        observability: Observability::NotObservable {
                            reason: "model was not executed for this candidate".to_owned(),
                        },
                    },
                    link,
                ),
            );
            continue;
        }
        for record in source.evidence {
            if ContentDigest::sha256(&record.record) != record.digest {
                return Err(EventFusionError::Evidence);
            }
            let id = record.digest.to_text();
            let mut link = ScoreLink {
                evidence_id: id.clone(),
                sensor: source.sensor.to_owned(),
                source_record: Some(record.digest),
                score_bits: None,
                score_ppm: None,
                calibration: None,
            };
            let (calibration, observability) = match &record.outcome {
                EvidenceOutcome::Associated { detection, .. }
                    if detection.class_index == profile.spec.class_index =>
                {
                    if detection.label != label {
                        return Err(EventFusionError::Evidence);
                    }
                    let ppm = score_interval(detection.score)?;
                    link.score_bits = Some(detection.score.to_bits());
                    link.score_ppm = Some(ppm);
                    let calibration = match binding {
                        Some(b) => {
                            let lo = b
                                .calibration
                                .bin(ppm[0])
                                .ok_or(EventFusionError::Evidence)?
                                .llr;
                            let hi = b
                                .calibration
                                .bin(ppm[1])
                                .ok_or(EventFusionError::Evidence)?
                                .llr;
                            link.calibration = Some(b.calibration.digest);
                            Calibration::Calibrated {
                                generation: format!(
                                    "{}@{}",
                                    b.calibration.generation, b.calibration.digest
                                ),
                                llr: lo.hull(hi),
                            }
                        }
                        None => Calibration::Uncalibrated {
                            reason: "no calibration bound to this retained sensor".to_owned(),
                        },
                    };
                    (calibration, Observability::Observed)
                }
                EvidenceOutcome::Associated { .. } | EvidenceOutcome::NoAssociation { .. } => (
                    Calibration::Uncalibrated {
                        reason: "no calibrated negative observation of the requested class"
                            .to_owned(),
                    },
                    Observability::Observed,
                ),
                EvidenceOutcome::BudgetExhausted | EvidenceOutcome::Refused(_) => (
                    Calibration::Uncalibrated {
                        reason: "model did not produce a usable score".to_owned(),
                    },
                    Observability::NotObservable {
                        reason: record.outcome.as_str().to_owned(),
                    },
                ),
            };
            let row = (
                EvidenceItem {
                    id: id.clone(),
                    sensor: source.sensor.to_owned(),
                    failure_domains: domains.clone(),
                    calibration,
                    observability,
                },
                link,
            );
            if rows.get(&id).is_some_and(|old| old != &row) {
                return Err(EventFusionError::Evidence);
            }
            rows.insert(id, row);
        }
    }
    let (evidence, scores): (Vec<_>, Vec<_>) = rows.into_values().unzip();
    let mut q = query(&profile.spec, &input.candidate.to_text(), evidence);
    q.kind = format!("associated_detector_class:{label}");
    let outcome = fuse(&q).map_err(|_| EventFusionError::Evidence)?;
    let mut e = CanonicalEncoder::new();
    e.text("fss.event_class_fusion.candidate.v1");
    for d in [
        context,
        input.candidate,
        input.proposal,
        input.provenance,
        outcome.query_digest,
        outcome.decision_digest,
    ] {
        e.digest(d);
    }
    e.u64(scores.len() as u64);
    for link in &scores {
        e.text(&link.evidence_id);
        e.text(&link.sensor);
        e.bool(link.source_record.is_some());
        if let Some(d) = link.source_record {
            e.digest(d);
        }
        e.bool(link.score_bits.is_some());
        if let Some(bits) = link.score_bits {
            e.u32(bits);
        }
        e.bool(link.score_ppm.is_some());
        if let Some([lo, hi]) = link.score_ppm {
            e.u32(lo);
            e.u32(hi);
        }
        e.bool(link.calibration.is_some());
        if let Some(d) = link.calibration {
            e.digest(d);
        }
    }
    Ok(CandidateFusion {
        candidate: input.candidate,
        native_proposal: input.proposal,
        native_provenance: input.provenance,
        query: q,
        outcome,
        scores,
        binding_digest: digest(e)?,
    })
}

fn score_interval(score: f32) -> Result<[u32; 2]> {
    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
        return Err(EventFusionError::Evidence);
    }
    // Every F32 * 1,000,000 product fits exactly in the F64 significand. Never round a
    // just-below-bin-boundary score up into an artificially strong likelihood interval.
    let ppm = f64::from(score) * 1_000_000.0;
    Ok([ppm.floor() as u32, ppm.ceil() as u32])
}

#[cfg(test)]
mod tests;
