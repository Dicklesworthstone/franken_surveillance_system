#![forbid(unsafe_code)]
//! Read-only, source-authenticated package tracks for conditional anonymous handoff analysis.
//!
//! Existing package custody and tracking owners supply the actual observations. This consumer
//! does not execute models, manufacture event intervals, infer synchronization, or publish an
//! identity claim. Every result is bound to one exact current authority anchor. A caller must
//! revalidate immediately before releasing a derived result held across additional work.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use fss_core::{ContentDigest, LedgerAnchor, SensorCapsule, SensorId};
use fss_graph_algorithms::continuity::ContinuityQuery;

use super::package_event::{PackageAnalysisReport, PackageEventError, PackageTrackingConfig};
use super::privacy_mask::{MaskBinding, current_mask};
use super::recorded_decode::{RecordedDecodeError, source_capsule};
use super::retained::SourceReadBudget;
use super::{RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

/// Pure public request and binding shapes. These types alone do not authenticate source custody.
pub mod contract;
pub use contract::{
    PackageClockAlignment, PackageHandoffBinding, PackageHandoffContractError,
    PackageHandoffObservation, PackageHandoffRequest, PackageHandoffSelection,
    PackageHandoffTracking,
};

/// Complete refusal of a retained query; no partial tracklet or fabricated singleton is returned.
#[derive(Debug)]
pub enum PackageHandoffError {
    /// Invalid declaration or unrepresentable conservative clock interval.
    Contract(PackageHandoffContractError),
    /// Existing package owner could not reconstruct its exact retained analysis.
    Package(Box<PackageEventError>),
    /// Exact source-capsule, import, current-mask or byte custody could not be established.
    Source(Box<RecordedDecodeError>),
    /// Deployment authority could not be verified at its durable head.
    Authority(Box<ReferenceError>),
    /// The selected native track is absent; aliases never create new native tracks.
    TrackUnavailable,
    /// Source facts contradict the exact selection or each other.
    Mismatch(&'static str),
    /// Authority, context or custody changed since the sealed projection was built.
    Stale(&'static str),
    /// Owner cancellation or caller deadline; no successful output is released.
    Cancelled,
}

impl PackageHandoffError {
    /// Stable machine refusal identity; nested custody owners retain their existing identities.
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Contract(_) => "ERR-PACKAGE-HANDOFF-REQUEST-001",
            Self::Package(error) => error.stable_id(),
            Self::Source(error) => error.stable_id(),
            Self::Authority(_) | Self::Stale(_) => "ERR-PACKAGE-HANDOFF-STALE-001",
            Self::TrackUnavailable => "ERR-PACKAGE-HANDOFF-TRACK-001",
            Self::Mismatch(_) => "ERR-PACKAGE-HANDOFF-MISMATCH-001",
            Self::Cancelled => "ERR-PACKAGE-HANDOFF-CANCELLED-001",
        }
    }
}

impl fmt::Display for PackageHandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => error.fmt(f),
            Self::Package(error) => write!(f, "retained handoff package custody: {error}"),
            Self::Source(error) => write!(f, "retained handoff source custody: {error}"),
            Self::Authority(error) => write!(f, "retained handoff authority: {error}"),
            Self::TrackUnavailable => f.write_str("selected native package track is unavailable"),
            Self::Mismatch(why) => write!(f, "retained handoff source mismatch: {why}"),
            Self::Stale(why) => write!(f, "retained handoff projection is stale: {why}"),
            Self::Cancelled => f.write_str("retained handoff query cancelled"),
        }
    }
}
impl std::error::Error for PackageHandoffError {}
impl From<PackageHandoffContractError> for PackageHandoffError {
    fn from(value: PackageHandoffContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<PackageEventError> for PackageHandoffError {
    fn from(value: PackageEventError) -> Self {
        Self::Package(Box::new(value))
    }
}
impl From<RecordedDecodeError> for PackageHandoffError {
    fn from(value: RecordedDecodeError) -> Self {
        Self::Source(Box::new(value))
    }
}
type Result<T> = std::result::Result<T, PackageHandoffError>;
type Recipe = (ContentDigest, String, PackageHandoffTracking);

struct AnalysisInputs {
    report: PackageAnalysisReport,
    source: RetainedFileImport,
    capsules: BTreeMap<u64, (SensorCapsule, ContentDigest)>,
    privacy: MaskBinding,
}

fn checkpoint(cx: &ReplayCx, cancelled: &impl Fn() -> bool, stage: &'static str) -> Result<()> {
    if cancelled() {
        cx.request_cancellation();
    }
    cx.checkpoint(stage)
        .map_err(|_| PackageHandoffError::Cancelled)
}

fn verify_head(deployment: &ReferenceDeployment) -> Result<()> {
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(ReferenceError::from)
        .map_err(|error| PackageHandoffError::Authority(Box::new(error)))
}

/// Opaque projection authenticated by the existing retained package and import owners.
/// Public bindings are descriptive; no public constructor can turn arbitrary bindings into this.
#[derive(Clone, Debug)]
pub struct PackageHandoffProjection {
    root: PathBuf,
    principal: String,
    request: PackageHandoffRequest,
    anchor: LedgerAnchor,
    query: ContinuityQuery,
    bindings: Vec<PackageHandoffBinding>,
    bytes: Vec<u8>,
    digest: ContentDigest,
    source_budget: SourceReadBudget,
}

impl PackageHandoffProjection {
    /// Rebuild every selected analysis from exact current retained custody without model execution.
    pub fn read(
        deployment: &ReferenceDeployment,
        request: &PackageHandoffRequest,
        cx: &ReplayCx,
    ) -> Result<Self> {
        Self::read_with_cancel(deployment, request, cx, &|| false)
    }

    /// Cancellation-aware read, bounded to four analysis recipes and 256 source frames per pass.
    /// Existing owners additionally checkpoint each source frame and each tracker frame on `cx`.
    pub fn read_with_cancel(
        deployment: &ReferenceDeployment,
        request: &PackageHandoffRequest,
        cx: &ReplayCx,
        cancelled: &impl Fn() -> bool,
    ) -> Result<Self> {
        Self::read_with_source_limit(
            deployment,
            request,
            cx,
            cancelled,
            contract::MAX_PACKAGE_HANDOFF_SOURCE_BYTES,
        )
    }

    /// Same source-authenticated read with a stricter cumulative original-byte allowance.
    /// The nonzero allowance cannot exceed 4 GiB. Every cloned projection and revalidation
    /// shares the original reservation counter, including unsuccessful reads; it never resets.
    pub fn read_with_source_limit(
        deployment: &ReferenceDeployment,
        request: &PackageHandoffRequest,
        cx: &ReplayCx,
        cancelled: &impl Fn() -> bool,
        maximum_source_bytes: u64,
    ) -> Result<Self> {
        if maximum_source_bytes == 0
            || maximum_source_bytes > contract::MAX_PACKAGE_HANDOFF_SOURCE_BYTES
        {
            return Err(PackageHandoffContractError::Limit.into());
        }
        Self::read_budgeted(
            deployment,
            request,
            cx,
            cancelled,
            SourceReadBudget::new(maximum_source_bytes),
        )
    }

    fn read_budgeted(
        deployment: &ReferenceDeployment,
        request: &PackageHandoffRequest,
        cx: &ReplayCx,
        cancelled: &impl Fn() -> bool,
        source_budget: SourceReadBudget,
    ) -> Result<Self> {
        request.validate()?;
        checkpoint(cx, cancelled, "package_handoffs:begin")?;
        if cx.root_dir() != deployment.root() {
            return Err(PackageHandoffError::Stale(
                "context belongs to another deployment",
            ));
        }
        verify_head(deployment)?;
        let anchor = deployment.current_anchor().clone();
        let mut analyses: BTreeMap<Recipe, AnalysisInputs> = BTreeMap::new();
        let mut frame_reads = 0_usize;
        let mut selections: Vec<_> = request.selections.iter().collect();
        selections.sort_unstable_by(|a, b| a.id.cmp(&b.id));
        for selected in &selections {
            let recipe = (
                selected.report_digest,
                selected.label.clone(),
                selected.tracking,
            );
            if analyses.contains_key(&recipe) {
                continue;
            }
            checkpoint(cx, cancelled, "package_handoffs:analysis")?;
            let report = PackageAnalysisReport::read_with_source_budget(
                deployment,
                selected.report_digest,
                &selected.label,
                PackageTrackingConfig {
                    confirmation_hits: selected.tracking.confirmation_hits,
                    maximum_missed_frames: selected.tracking.maximum_missed_frames,
                    minimum_iou_ppm: selected.tracking.minimum_iou_ppm,
                },
                Some(&source_budget),
                cx,
            )?;
            checkpoint(cx, cancelled, "package_handoffs:analysis_complete")?;
            let record = report.retained().record();
            frame_reads = frame_reads
                .checked_add(record.frames.len())
                .ok_or(PackageHandoffContractError::Limit)?;
            if record.frames.is_empty()
                || record.frames.len() > contract::MAX_PACKAGE_HANDOFF_FRAMES
                || frame_reads > contract::MAX_PACKAGE_HANDOFF_FRAME_READS
            {
                return Err(PackageHandoffContractError::Limit.into());
            }
            let source = RetainedFileImport::open(
                deployment,
                record.import_identity,
                RetainedReadLimits::default(),
                cx,
            )
            .map_err(RecordedDecodeError::from)?;
            if source.import_root() != record.import_root
                || source.manifest().format != record.media_format
            {
                return Err(PackageHandoffError::Mismatch("retained import identity"));
            }
            let sensor =
                SensorId::parse(&record.frames[0].sensor_id).map_err(RecordedDecodeError::from)?;
            let privacy = current_mask(deployment, &sensor).map_err(RecordedDecodeError::from)?;
            let mut capsules = BTreeMap::new();
            for frame in &record.frames {
                checkpoint(cx, cancelled, "package_handoffs:capsule")?;
                let index = usize::try_from(frame.segment)
                    .map_err(|_| PackageHandoffContractError::Limit)?;
                let (capsule, digest) = source_capsule(deployment, &source, index)?;
                if digest != frame.capsule_digest
                    || capsule.sensor_id.as_str() != frame.sensor_id
                    || capsule.capture != frame.capture
                    || capsules.insert(frame.segment, (capsule, digest)).is_some()
                {
                    return Err(PackageHandoffError::Mismatch("exact source frame"));
                }
            }
            analyses.insert(
                recipe,
                AnalysisInputs {
                    report,
                    source,
                    capsules,
                    privacy,
                },
            );
        }
        let mut bindings = Vec::with_capacity(selections.len());
        for selected in selections {
            checkpoint(cx, cancelled, "package_handoffs:track")?;
            let inputs = analyses
                .get(&(
                    selected.report_digest,
                    selected.label.clone(),
                    selected.tracking,
                ))
                .ok_or(PackageHandoffError::Mismatch("analysis recipe missing"))?;
            bindings.push(binding(inputs, selected, cx, cancelled)?);
        }
        // Recheck current policy after all joins. Custody reads above already verified every
        // source frame, including unmatched frames on which native tracking/reset decisions rely.
        for inputs in analyses.values() {
            checkpoint(cx, cancelled, "package_handoffs:privacy_revalidate")?;
            let sensor = SensorId::parse(&inputs.report.retained().record().frames[0].sensor_id)
                .map_err(RecordedDecodeError::from)?;
            let privacy = current_mask(deployment, &sensor).map_err(RecordedDecodeError::from)?;
            if privacy.digest() != inputs.privacy.digest()
                || privacy.generation() != inputs.privacy.generation()
            {
                return Err(PackageHandoffError::Stale("source privacy changed"));
            }
        }
        verify_head(deployment)?;
        if deployment.current_anchor() != &anchor {
            return Err(PackageHandoffError::Stale("authority anchor changed"));
        }
        let query = contract::continuity_query(&anchor, request, &bindings)?;
        let bytes = contract::projection_bytes(&anchor, request, &bindings)?;
        checkpoint(cx, cancelled, "package_handoffs:complete")?;
        Ok(Self {
            root: deployment.root().to_path_buf(),
            principal: cx.io_authority().principal().to_owned(),
            request: request.clone(),
            anchor,
            query,
            bindings,
            digest: ContentDigest::sha256(&bytes),
            bytes,
            source_budget,
        })
    }

    /// Exact native conditional declaration derived from source facts and explicit assumptions.
    #[must_use]
    pub fn query(&self) -> &ContinuityQuery {
        &self.query
    }
    /// Complete authority anchor at construction, not merely its state root.
    #[must_use]
    pub fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Every selected track's complete source provenance and actual assigned observations.
    #[must_use]
    pub fn bindings(&self) -> &[PackageHandoffBinding] {
        &self.bindings
    }
    /// Complete canonical projection payload, suitable for exact digest pinning.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
    /// SHA-256 of the complete canonical projection payload.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Original bytes reserved across initial read and all revalidation attempts, including
    /// HTTP/RTSP original-provenance reads. Cache hits do not reserve the same loaded bytes again.
    #[must_use]
    pub fn source_bytes_read(&self) -> u64 {
        self.source_budget.used()
    }

    /// Reopen all selected retained custody and rederive the exact projection before release.
    pub fn revalidate(&self, deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
        self.revalidate_with_cancel(deployment, cx, &|| false)
    }

    /// Revalidation repeats the same bounded source pass, without models or publication.
    /// Exact anchor/principal/root pins refuse changed authority even if timestamps look similar.
    pub fn revalidate_with_cancel(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        checkpoint(cx, cancelled, "package_handoffs:revalidate")?;
        if self.root != deployment.root()
            || cx.root_dir() != deployment.root()
            || self.principal != cx.io_authority().principal()
            || self.anchor != *deployment.current_anchor()
        {
            return Err(PackageHandoffError::Stale(
                "deployment, principal or full anchor changed",
            ));
        }
        let fresh = Self::read_budgeted(
            deployment,
            &self.request,
            cx,
            cancelled,
            self.source_budget.clone(),
        )?;
        if self.bytes != fresh.bytes || self.query != fresh.query || self.anchor != fresh.anchor {
            return Err(PackageHandoffError::Stale(
                "retained source projection changed",
            ));
        }
        checkpoint(cx, cancelled, "package_handoffs:revalidated")
    }
}

fn binding(
    inputs: &AnalysisInputs,
    selected: &PackageHandoffSelection,
    cx: &ReplayCx,
    cancelled: &impl Fn() -> bool,
) -> Result<PackageHandoffBinding> {
    let report = &inputs.report;
    let retained = report.retained();
    let record = retained.record();
    let track = report
        .tracks()
        .iter()
        .find(|track| track.identity == selected.track)
        .ok_or(PackageHandoffError::TrackUnavailable)?;
    let first = track
        .observations
        .first()
        .ok_or(PackageHandoffError::TrackUnavailable)?;
    let first_frame = record
        .frames
        .iter()
        .find(|frame| {
            frame.segment == first.segment && frame.capsule_digest == first.capsule_digest
        })
        .ok_or(PackageHandoffError::Mismatch("track frame missing"))?;
    let (first_capsule, _) = inputs
        .capsules
        .get(&first.segment)
        .ok_or(PackageHandoffError::Mismatch("track capsule missing"))?;
    if selected.alignment.import_identity != record.import_identity
        || selected.alignment.stream_id != first_capsule.stream_id.as_str()
        || selected.alignment.clock_basis != first_capsule.clock_basis
    {
        return Err(PackageHandoffError::Mismatch(
            "clock declaration does not pin actual source",
        ));
    }
    let mut observations = Vec::with_capacity(track.observations.len());
    for (index, observed) in track.observations.iter().enumerate() {
        checkpoint(cx, cancelled, "package_handoffs:observation")?;
        let frame = record
            .frames
            .iter()
            .find(|frame| {
                frame.segment == observed.segment && frame.capsule_digest == observed.capsule_digest
            })
            .ok_or(PackageHandoffError::Mismatch(
                "assigned detection frame missing",
            ))?;
        let (capsule, digest) =
            inputs
                .capsules
                .get(&observed.segment)
                .ok_or(PackageHandoffError::Mismatch(
                    "assigned source capsule missing",
                ))?;
        if *digest != observed.capsule_digest
            || capsule.sensor_id != first_capsule.sensor_id
            || capsule.stream_id != first_capsule.stream_id
            || capsule.clock_basis != first_capsule.clock_basis
            || frame.dimensions != first_frame.dimensions
        {
            return Err(PackageHandoffError::Mismatch(
                "track crosses a source generation",
            ));
        }
        let (row, score_bits, bounds, _) = observed.detection.ok_or(
            PackageHandoffError::Mismatch("native sample lacks its actual assignment"),
        )?;
        if !frame.detections.iter().any(|detection| {
            detection.row == row
                && detection.class_index == report.class_index()
                && detection.score_bits == score_bits
                && detection.bounds == bounds
        }) {
            return Err(PackageHandoffError::Mismatch(
                "assigned detector row differs from retained output",
            ));
        }
        let capture = [capsule.capture.earliest.0, capsule.capture.latest.0];
        observations.push(PackageHandoffObservation {
            segment: observed.segment,
            capsule_digest: *digest,
            source_digest: capsule.source_digest,
            capture,
            aligned_capture: selected.alignment.align(capture)?,
            detection_row: row,
            class_index: report.class_index(),
            score_bits,
            bounds,
            inference_identity: frame.inference_identity,
            output_digest: frame.output_digest,
            detection_report_digest: frame.detection_report_digest,
            confirmed: report.sample_is_confirmed(track.identity, index).ok_or(
                PackageHandoffError::Mismatch("native confirmation sample missing"),
            )?,
        });
    }
    let mut result = PackageHandoffBinding {
        id: selected.id.clone(),
        report_digest: record.report_digest,
        analysis_digest: report.digest(),
        record_digest: retained.record_digest(),
        retained_root: retained.root(),
        import_identity: record.import_identity,
        import_root: record.import_root,
        retained_anchor: retained.authority_anchor().clone(),
        track: track.identity,
        sensor_id: first_capsule.sensor_id.as_str().to_owned(),
        stream_id: first_capsule.stream_id.as_str().to_owned(),
        clock_basis: first_capsule.clock_basis,
        capture_time_label: inputs.source.manifest().capture_time_label.clone(),
        dimensions: first_frame.dimensions,
        camera_generation: contract::camera_generation(
            first_capsule.sensor_id.as_str(),
            first_capsule.stream_id.as_str(),
            first_frame.dimensions,
        )?,
        calibration: selected.calibration,
        model: record.model_digest,
        package_digest: record.package_digest,
        manifest_digest: record.manifest_digest,
        model_digest: record.model_digest,
        graph_digest: record.graph_digest,
        contract_digest: record.contract_digest,
        model_id: record.model_id.clone(),
        model_generation: record.generation.clone(),
        label: report.label().to_owned(),
        class_index: report.class_index(),
        tracking: selected.tracking,
        privacy_binding: inputs.privacy.digest(),
        privacy_policy: inputs.privacy.policy_digest(),
        alignment: selected.alignment.clone(),
        observations,
        confirmed: track.confirmed,
    };
    result.model = contract::model_comparison_key(&result);
    Ok(result)
}
