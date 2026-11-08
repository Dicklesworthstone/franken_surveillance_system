#![forbid(unsafe_code)]
//! Source-verified native package tracks evaluated against one explicitly labelled clip.
//!
//! The public owner opens an existing deployment, reuses its actual retained package and source
//! readers, and returns a completed derived snapshot. It neither runs a model nor publishes
//! evaluation, event, calibration, threshold, or effect authority. Local publisher recovery may
//! perform housekeeping while opening the store; pending external effects are not reconciled.

use std::fmt;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest, SensorId};

use super::package_event::{PackageAnalysisReport, PackageEventError};
use super::privacy_mask::current_mask;
use super::recorded_decode::{RecordedDecodeError, source_capsule};
use super::retained::SourceReadBudget;
use super::{RetainedFileImport, RetainedReadLimits};
use crate::evaluation::{
    EvaluationError, EvaluationPolicy, EvaluationReport, LabelSet, evaluate_cancellable,
};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Pure extraction shapes and policy. Public facts alone never authenticate source custody.
pub mod contract;
pub use contract::{
    MAX_PACKAGE_EVALUATION_MATCHING_CELLS, MAX_PACKAGE_EVALUATION_SOURCE_BYTES,
    PackageEvaluationError, PackageEvaluationProjection, PackageEvaluationRequest,
};

use contract::{
    PackageEvaluationFrameBinding, PackageEvaluationSourceBinding, project_package_candidates,
};

/// Schema of a completed native-source evaluation snapshot.
pub const RETAINED_PACKAGE_EVALUATION_SCHEMA: &str = "fss.retained_package_evaluation.v1";

/// Complete refusal: no partial candidate set or successful score is returned.
#[derive(Debug)]
pub enum RetainedPackageEvaluationError {
    /// Clip, clock, generation, extraction, or bounded-work contract was not satisfied.
    Contract(PackageEvaluationError),
    /// Existing native package custody or deterministic tracking could not be reconstructed.
    Package(Box<PackageEventError>),
    /// Original source, capsule, or current privacy custody could not be re-established.
    Source(Box<RecordedDecodeError>),
    /// Existing deployment authority could not be opened or checked at its durable head.
    Authority(Box<ReferenceError>),
    /// Label or evaluation policy validation, matching budget, or cooperative cancellation.
    Evaluation(EvaluationError),
    /// Exact source, root, current authority, or re-derived projection changed.
    Mismatch(&'static str),
    /// The explicit cumulative source-read allowance is outside the admitted range.
    SourceLimit,
    /// The caller cancelled; no successful output is released.
    Cancelled,
}

impl RetainedPackageEvaluationError {
    /// Stable machine identity. Diagnostics do not disclose local paths or source rows.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Contract(error) => error.code(),
            Self::Package(error) => error.stable_id(),
            Self::Source(error) => error.stable_id(),
            Self::Authority(_) => "evaluation.retained.authority",
            Self::Evaluation(error) => error.code(),
            Self::Mismatch(_) => "evaluation.retained.mismatch",
            Self::SourceLimit => "evaluation.retained.source_limit",
            Self::Cancelled => "evaluation.cancelled",
        }
    }
}

impl fmt::Display for RetainedPackageEvaluationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => error.fmt(f),
            Self::Package(error) => write!(f, "native package evaluation custody: {error}"),
            Self::Source(error) => write!(f, "native package evaluation source: {error}"),
            Self::Authority(error) => write!(f, "native package evaluation authority: {error}"),
            Self::Evaluation(error) => error.fmt(f),
            Self::Mismatch(reason) => write!(f, "native package evaluation mismatch: {reason}"),
            Self::SourceLimit => f.write_str("native package evaluation source allowance refused"),
            Self::Cancelled => f.write_str("native package evaluation cancelled"),
        }
    }
}

impl std::error::Error for RetainedPackageEvaluationError {}
impl From<PackageEvaluationError> for RetainedPackageEvaluationError {
    fn from(error: PackageEvaluationError) -> Self {
        Self::Contract(error)
    }
}
impl From<PackageEventError> for RetainedPackageEvaluationError {
    fn from(error: PackageEventError) -> Self {
        match error {
            PackageEventError::Cancelled => Self::Cancelled,
            error => Self::Package(Box::new(error)),
        }
    }
}
impl From<RecordedDecodeError> for RetainedPackageEvaluationError {
    fn from(error: RecordedDecodeError) -> Self {
        match error {
            RecordedDecodeError::Cancelled => Self::Cancelled,
            error => Self::Source(Box::new(error)),
        }
    }
}
impl From<ReferenceError> for RetainedPackageEvaluationError {
    fn from(error: ReferenceError) -> Self {
        Self::Authority(Box::new(error))
    }
}
impl From<EvaluationError> for RetainedPackageEvaluationError {
    fn from(error: EvaluationError) -> Self {
        Self::Evaluation(error)
    }
}

type Result<T> = std::result::Result<T, RetainedPackageEvaluationError>;

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| RetainedPackageEvaluationError::Cancelled)
}

fn verify_head(deployment: &ReferenceDeployment) -> Result<()> {
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(ReferenceError::from)?;
    Ok(())
}

/// A completed evaluation of actual retained output, verified against one authority snapshot.
/// Its public projection is descriptive; it is not an effect grant or coverage certificate.
#[derive(Debug)]
pub struct RetainedPackageEvaluation {
    projection: PackageEvaluationProjection,
    report: EvaluationReport,
    source_bytes_read: u64,
    maximum_source_bytes: u64,
    digest: ContentDigest,
}

impl RetainedPackageEvaluation {
    /// Read every native input, score all admitted tracks, then independently repeat the source
    /// pass before returning. Both passes share one nonrenewing original-byte allowance.
    ///
    /// `root` must already be a complete deployment and exactly match `cx`. This owner never
    /// returns its internal deployment, and opening cannot create one or reconcile effects.
    /// Labels remain caller declarations; the source sample hull limits the selected window but
    /// supplies neither a camera-coverage witness nor an inferred final-frame duration.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        root: &Path,
        site_lineage: &str,
        request: &PackageEvaluationRequest,
        labels: &LabelSet,
        policy: &EvaluationPolicy,
        maximum_source_bytes: u64,
        cx: &ReplayCx,
    ) -> Result<Self> {
        request.validate()?;
        contract::validate_package_evaluation_inputs(request, labels, policy)?;
        if maximum_source_bytes == 0 || maximum_source_bytes > MAX_PACKAGE_EVALUATION_SOURCE_BYTES {
            return Err(RetainedPackageEvaluationError::SourceLimit);
        }
        checkpoint(cx, "package_evaluation:open")?;
        if cx.root_dir() != root {
            return Err(RetainedPackageEvaluationError::Mismatch("context root"));
        }
        let deployment = ReferenceDeployment::open_existing_without_effect_reconciliation(
            root,
            site_lineage,
            cx,
        )?;
        let source_budget = SourceReadBudget::new(maximum_source_bytes);
        let projection = read_projection(&deployment, request, labels, policy, &source_budget, cx)?;
        checkpoint(cx, "package_evaluation:score")?;
        let report = evaluate_cancellable(
            &projection.identity,
            policy,
            labels,
            &projection.candidates,
            MAX_PACKAGE_EVALUATION_MATCHING_CELLS,
            &|| cx.checkpoint("package_evaluation:matching").is_err(),
        )?;
        checkpoint(cx, "package_evaluation:revalidate")?;
        let fresh = read_projection(&deployment, request, labels, policy, &source_budget, cx)?;
        if projection != fresh {
            return Err(RetainedPackageEvaluationError::Mismatch(
                "source projection changed before result release",
            ));
        }
        verify_head(&deployment)?;
        checkpoint(cx, "package_evaluation:complete")?;
        let source_bytes_read = source_budget.used();
        let mut encoded = CanonicalEncoder::new();
        encoded.text(RETAINED_PACKAGE_EVALUATION_SCHEMA);
        encoded.digest(projection.digest);
        encoded.digest(report.digest);
        encoded.u64(source_bytes_read);
        encoded.u64(maximum_source_bytes);
        let digest = ContentDigest::sha256(&encoded.finish());
        Ok(Self {
            projection,
            report,
            source_bytes_read,
            maximum_source_bytes,
            digest,
        })
    }

    /// Exact first-confirmation candidates, full source pins, and every track's disposition.
    #[must_use]
    pub fn projection(&self) -> &PackageEvaluationProjection {
        &self.projection
    }
    /// Unchanged event-level evaluator output under the source-derived generation identities.
    #[must_use]
    pub fn report(&self) -> &EvaluationReport {
        &self.report
    }
    /// Original bytes reserved across both verification passes, including failed read attempts.
    #[must_use]
    pub fn source_bytes_read(&self) -> u64 {
        self.source_bytes_read
    }
    /// One cumulative allowance shared by source construction and final revalidation.
    #[must_use]
    pub fn maximum_source_bytes(&self) -> u64 {
        self.maximum_source_bytes
    }
    /// Digest binding the projection, evaluator report, and actual source-read accounting.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
}

fn read_projection(
    deployment: &ReferenceDeployment,
    request: &PackageEvaluationRequest,
    labels: &LabelSet,
    policy: &EvaluationPolicy,
    source_budget: &SourceReadBudget,
    cx: &ReplayCx,
) -> Result<PackageEvaluationProjection> {
    checkpoint(cx, "package_evaluation:read")?;
    verify_head(deployment)?;
    let anchor = deployment.current_anchor().clone();
    let analysis = PackageAnalysisReport::read_with_source_budget(
        deployment,
        request.report_digest,
        &request.label,
        request.tracking,
        Some(source_budget),
        cx,
    )?;
    checkpoint(cx, "package_evaluation:analysis_complete")?;
    let retained = analysis.retained();
    let record = retained.record();
    let source = RetainedFileImport::open(
        deployment,
        record.import_identity,
        RetainedReadLimits::default(),
        cx,
    )
    .map_err(RecordedDecodeError::from)?;
    if source.import_root() != record.import_root || source.manifest().format != record.media_format
    {
        return Err(RetainedPackageEvaluationError::Mismatch("retained import"));
    }
    let first = record
        .frames
        .first()
        .ok_or(RetainedPackageEvaluationError::Mismatch(
            "empty native analysis",
        ))?;
    let sensor = SensorId::parse(&first.sensor_id).map_err(RecordedDecodeError::from)?;
    let privacy = current_mask(deployment, &sensor).map_err(RecordedDecodeError::from)?;
    let mut frames = Vec::with_capacity(record.frames.len());
    for frame in &record.frames {
        checkpoint(cx, "package_evaluation:source_frame")?;
        let segment = usize::try_from(frame.segment)
            .map_err(|_| RetainedPackageEvaluationError::Mismatch("source segment index"))?;
        let (capsule, capsule_digest) = source_capsule(deployment, &source, segment)?;
        if capsule_digest != frame.capsule_digest
            || capsule.sensor_id.as_str() != frame.sensor_id
            || capsule.capture != frame.capture
        {
            return Err(RetainedPackageEvaluationError::Mismatch("source capsule"));
        }
        frames.push(PackageEvaluationFrameBinding {
            segment: frame.segment,
            capsule_digest,
            source_digest: capsule.source_digest,
            sensor_id: capsule.sensor_id.as_str().to_owned(),
            stream_id: capsule.stream_id.as_str().to_owned(),
            sequence: capsule.sequence,
            clock_basis: capsule.clock_basis,
            capture: capsule.capture,
            gap_before: capsule.gap_before,
        });
    }
    let source_binding = PackageEvaluationSourceBinding {
        site_lineage: deployment.site_lineage().to_owned(),
        principal: cx.io_authority().principal().to_owned(),
        analysis_digest: analysis.digest(),
        record_digest: retained.record_digest(),
        retained_root: retained.root(),
        retained_anchor: retained.authority_anchor().clone(),
        authority_anchor: anchor.clone(),
        import_manifest_digest: source.manifest_digest(),
        privacy_binding: privacy.digest(),
        privacy_policy: privacy.policy_digest(),
        capture_time_label: source.manifest().capture_time_label.clone(),
        non_container_omissions: source
            .manifest()
            .omission_spans
            .iter()
            .any(|span| span.len > 0 && !span.is_container_structure()),
        first_source_gap: source
            .manifest()
            .segment_spans
            .iter()
            .find(|span| span.segment_index > 0 && span.gap_before)
            .map(|span| span.segment_index as u64),
        frames,
        boundaries: analysis.boundaries().to_vec(),
    };
    let projection = project_package_candidates(
        request,
        &source_binding,
        record,
        analysis.tracks(),
        labels,
        policy,
        &|| cx.checkpoint("package_evaluation:projection").is_err(),
    )?;
    checkpoint(cx, "package_evaluation:privacy_revalidate")?;
    let current = current_mask(deployment, &sensor).map_err(RecordedDecodeError::from)?;
    if current.digest() != privacy.digest() || current.generation() != privacy.generation() {
        return Err(RetainedPackageEvaluationError::Mismatch(
            "current source privacy",
        ));
    }
    verify_head(deployment)?;
    if deployment.current_anchor() != &anchor {
        return Err(RetainedPackageEvaluationError::Mismatch("authority anchor"));
    }
    checkpoint(cx, "package_evaluation:projected")?;
    Ok(projection)
}
