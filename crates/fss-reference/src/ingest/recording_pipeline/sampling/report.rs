#![forbid(unsafe_code)]
//! Composite sampling provenance without a second detector/tracker wire format.

use super::*;

/// Existing 16 MiB analysis ceiling plus bounded sampling metadata; not process peak memory.
pub const MAX_SAMPLED_REPORT_BYTES: usize = MAX_ANALYSIS_REPORT_BYTES + 1024 * 1024;
const MAX_DECISION_BYTES: usize = 2048;
const REPORT_DOMAIN: &str = "fss.sampled_recording_report.v1";

/// A complete report. Decisions are privately constructed by source replay, not deserialized
/// into trusted observations. The nested AnalysisReport retains its own existing exact format.
#[derive(Clone, Debug)]
pub struct SampledReport {
    plan: SamplingPlan,
    decisions: Vec<SamplingDecision>,
    analysis: AnalysisReport,
    comparisons_used: u64,
    bytes: Vec<u8>,
    digest: ContentDigest,
}
impl SampledReport {
    pub(super) fn assemble(plan: SamplingPlan, decisions: Vec<SamplingDecision>, analysis: AnalysisReport,
        comparisons_used: u64) -> Result<Self, SamplingError>
    {
        if decisions.len() != plan.count || comparisons_used > plan.maximum_comparisons
            || analysis.plan().import_identity() != plan.import
        { return Err(SamplingError::Mismatch); }
        for (ordinal, decision) in decisions.iter().enumerate() {
            if decision.ordinal() != ordinal as u64 || decision.import_identity() != plan.import
                || decision.segment_index() != (plan.first + ordinal) as u64
                || decision.predecessor() != ordinal.checked_sub(1).map(|i| decisions[i].digest())
            { return Err(SamplingError::Mismatch); }
        }
        let selected: Vec<_> = decisions.iter().filter(|d| d.selected()).collect();
        if selected.len() != analysis.observations().len() { return Err(SamplingError::Mismatch); }
        for (decision, observed) in selected.iter().zip(analysis.observations()) {
            let detection = observed.detection();
            if decision.segment_index() != detection.segment_index()
                || decision.frame_root() != detection.frame_root()
                || decision.import_identity() != detection.import_identity()
            { return Err(SamplingError::Mismatch); }
        }
        let mut e = CanonicalEncoder::new();
        e.bytes(b"FSSASRP1"); e.u32(1); e.text(REPORT_DOMAIN); e.bytes(plan.encoded());
        e.u64(comparisons_used); e.u64(decisions.len() as u64);
        for decision in &decisions {
            let bytes = decision.encoded();
            if bytes.is_empty() || bytes.len() > MAX_DECISION_BYTES { return Err(SamplingError::Limit); }
            e.bytes(&bytes);
        }
        e.bytes(analysis.encoded());
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_SAMPLED_REPORT_BYTES { return Err(SamplingError::Limit); }
        Ok(Self { plan, decisions, analysis, comparisons_used,
            digest: ContentDigest::sha256(&bytes), bytes })
    }
    /// Revalidate ALL source frames (including skipped model invocations), recompute every
    /// decision and replay the existing detector/tracker report. This performs no JPEG/model
    /// numeric execution, writes no authority, and does not trust serialized tracks or decisions.
    ///
    /// The caller must admit at least the plan's bounded comparison allowance before any source
    /// read. Frame and nested analysis bounds come from limits; detector/association work is
    /// charged to the supplied cumulative AnalysisBudget. This is not a full process/IO budget.
    pub fn verify(
        deployment: &ReferenceDeployment, bytes: &[u8], expected: ContentDigest,
        limits: &AnalysisLimits, maximum_comparisons: u64, budget: &mut AnalysisBudget, cx: &ReplayCx,
    ) -> Result<Self, SamplingError> {
        check(cx)?;
        if bytes.len() > MAX_SAMPLED_REPORT_BYTES { return Err(SamplingError::Limit); }
        if ContentDigest::sha256(bytes) != expected { return Err(SamplingError::Mismatch); }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != b"FSSASRP1" || d.u32()? != 1 || d.text()? != REPORT_DOMAIN {
            return Err(SamplingError::InvalidPlan);
        }
        let plan_bytes = d.bytes()?;
        let plan = SamplingPlan::decode(plan_bytes, ContentDigest::sha256(plan_bytes))?;
        if limits.maximum_frames == 0 || limits.maximum_frames > MAX_ANALYSIS_FRAMES
            || limits.maximum_report_bytes == 0 || limits.maximum_report_bytes > MAX_ANALYSIS_REPORT_BYTES
            || plan.count > limits.maximum_frames || plan.maximum_comparisons > maximum_comparisons
        { return Err(SamplingError::Limit); }
        let claimed_work = d.u64()?;
        let n = bounded_count(&mut d, MAX_ANALYSIS_FRAMES)?;
        if n != plan.count || claimed_work > plan.maximum_comparisons { return Err(SamplingError::Mismatch); }
        // Validate the complete envelope and all bounded lengths before touching source custody.
        let mut encoded_decisions = Vec::with_capacity(n);
        for _ in 0..n {
            let decision = d.bytes()?;
            if decision.is_empty() || decision.len() > MAX_DECISION_BYTES { return Err(SamplingError::Limit); }
            encoded_decisions.push(decision);
        }
        let analysis_bytes = d.bytes()?;
        if analysis_bytes.len() > limits.maximum_report_bytes { return Err(SamplingError::Limit); }
        d.ensure_finished()?;
        let mut sampler = ActivitySampler::new(plan.policy, plan.maximum_comparisons)?;
        let mut decisions = Vec::with_capacity(n);
        for (ordinal, encoded) in encoded_decisions.iter().enumerate() {
            check(cx)?;
            let index = plan.first + ordinal; // checked range was frozen by SamplingPlan::build.
            let frame = RecordedFrame::open(deployment, &plan.source(index, limits), cx)?;
            let decision = sampler.push(&frame, plan.required.get(&index).copied(), cx)?;
            if decision.encoded().as_slice() != *encoded { return Err(SamplingError::Mismatch); }
            decisions.push(decision);
        }
        if sampler.comparisons_used() != claimed_work { return Err(SamplingError::Mismatch); }
        let analysis = AnalysisReport::verify(deployment, analysis_bytes, ContentDigest::sha256(analysis_bytes),
            limits, budget, cx)?;
        check(cx)?;
        let report = Self::assemble(plan, decisions, analysis, sampler.comparisons_used())?;
        if report.encoded() != bytes { return Err(SamplingError::Mismatch); }
        Ok(report)
    }
    /// Frozen source range and explicit policy/requirement recipe.
    #[must_use]
    pub fn plan(&self) -> &SamplingPlan { &self.plan }
    /// One ordered immutable decision for every requested source frame, without truncation.
    #[must_use]
    pub fn decisions(&self) -> &[SamplingDecision] { &self.decisions }
    /// Existing complete sparse analysis; gaps retain source/association uncertainty.
    #[must_use]
    pub fn analysis(&self) -> &AnalysisReport { &self.analysis }
    /// Model invocations deliberately omitted, not negative detections or deleted media.
    #[must_use]
    pub fn skipped_frames(&self) -> usize { self.decisions.iter().filter(|d| !d.selected()).count() }
    /// Numeric pixel comparisons actually consumed by the exact replay recipe.
    #[must_use]
    pub fn comparisons_used(&self) -> u64 { self.comparisons_used }
    /// Complete bounded versioned envelope for caller-owned retention or export.
    #[must_use]
    pub fn encoded(&self) -> &[u8] { &self.bytes }
    /// Integrity identity. Verification requires source replay, not only hashing these bytes.
    #[must_use]
    pub fn digest(&self) -> ContentDigest { self.digest }
}
fn check(cx: &ReplayCx) -> Result<(), SamplingError> {
    cx.checkpoint("sampled_recording:verify").map_err(|_| SamplingError::Cancelled)
}
