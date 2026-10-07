#![forbid(unsafe_code)]
//! `file-activity`: the lab scenario whose model result is computed, not scripted (fss-2h5zq.51).
//!
//! A recorded single-camera JPEG frame sequence (checked-in fss-codec-mjpeg fixtures) is staged
//! as source bytes with sensor capsules, natively decoded to RGB, and every frame after the first
//! is scored by the `model:fss-activity:v1` graph on the scalar executor against the first frame.
//! The graph is loaded only from the committed, digest-pinned model package after verification
//! (fss-2h5zq.49), and the package archive is retained beside the receipts.
//! The documented threshold policy turns each score into an executor-backed observation for the
//! unchanged unknown-presence policy. Every observation binds the retained invocation receipt and
//! decode receipt records, and carries continuity `not_observable: file_source`; a file never
//! certifies absence and one camera is never corroborated. The score is uncalibrated pixel
//! change; this fixture is not accuracy evidence.

use fss_codec_mjpeg::color::{DecodedRgb, RgbDecodeLimits, decode_rgb};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget};
use fss_core::{
    CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest, SensorCapsule,
    SensorId, SensorSourceBytesSpec, StreamId,
};
use fss_reference::executor_activity::{
    ACTIVITY_MODEL_GENERATION, ActivityExecutorModel, ActivityFrameBinding,
    ActivityThresholdPolicy, ExecutorContinuity, ExecutorModelOutcome, ExecutorModelResult,
    rgb_decode_receipt_bytes,
};
use fss_reference::executor_activity_package::ACTIVITY_PACKAGE_V1;
use fss_reference::{ExecBudget, ReferenceDeployment, ReferenceModelObservation, ScalarExecCx};

use crate::scenario::ScenarioError;

/// Sensor of the recorded file.
pub const FILE_SENSOR: &str = "file-cam";
/// Failure domain of the recorded file: one camera, one domain.
pub const FILE_FAILURE_DOMAIN: &str = "file:lab-recording";

/// The recorded frame sequence: a flat background twice, then a frame with real content.
/// Frame 0 is the reference; frame 1 is expected below threshold and frame 2 above it.
const FRAMES: [&[u8]; 3] = [
    include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/background.jpg"),
    include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/background.jpg"),
    include_bytes!("../../../../fss-codec-mjpeg/tests/fixtures/gray.jpg"),
];

/// Lab-chosen executor ceilings (the graph needs a few thousand multiply-adds).
const EXECUTOR_MACS: u64 = 10_000_000;
const EXECUTOR_BYTES: usize = 16 * 1024 * 1024;

/// Test-only knobs; the CLI always runs [`FileActivityOptions::default`].
#[derive(Clone, Copy, Debug)]
pub struct FileActivityOptions {
    /// Threshold policy generation applied to every frame.
    pub policy: ActivityThresholdPolicy,
    /// Frame index whose invocation is starved of budget (executor failure injection).
    pub starve_frame: Option<usize>,
}

impl FileActivityOptions {
    /// The reference policy and no injected failure.
    pub fn reference() -> Result<Self, ScenarioError> {
        Ok(Self {
            policy: ActivityThresholdPolicy::reference()
                .map_err(|e| ScenarioError::Reference(e.to_string()))?,
            starve_frame: None,
        })
    }
}

/// One executor-backed observation as reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileActivityObservation {
    /// Frame index within the recording.
    pub frame: usize,
    /// Retained result.
    pub result: ExecutorModelResult,
    /// Retained result object digest.
    pub result_digest: ContentDigest,
}

/// Executor section of the `file-activity` report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileActivityReport {
    /// Graph, preprocessing and weights identity.
    pub model_digest: ContentDigest,
    /// Whole-archive SHA-256 of the verified model package (retained in the deployment).
    pub package_sha256: ContentDigest,
    /// Verified package manifest digest, the receipts' `modelPackageRoot`.
    pub model_package_root: ContentDigest,
    /// Threshold policy applied.
    pub policy: ActivityThresholdPolicy,
    /// Retained decode receipt record of the reference frame.
    pub reference_decode_receipt: ContentDigest,
    /// One per evaluated frame.
    pub observations: Vec<FileActivityObservation>,
}

impl FileActivityReport {
    /// Renders the `executor` object.
    pub fn render_json(&self, output: &mut String) {
        use std::fmt::Write as _;
        let _ = write!(
            output,
            "{{\"source\":\"file\",\"sensor\":\"sensor:{FILE_SENSOR}\",\"model_generation\":\"{ACTIVITY_MODEL_GENERATION}\",\"model_digest\":\"{}\",\"package_sha256\":\"{}\",\"model_package_root\":\"{}\",\"backend\":\"scalar_reference\",\"threshold_policy\":{{\"generation\":{},\"threshold\":{},\"rule\":\"activity_if_score_strictly_greater\",\"digest\":\"{}\"}},\"score_calibrated\":false,\"reference_decode_receipt\":\"{}\",\"observations\":[",
            self.model_digest,
            self.package_sha256,
            self.model_package_root,
            self.policy.generation(),
            self.policy.threshold(),
            self.policy.digest(),
            self.reference_decode_receipt,
        );
        for (index, observation) in self.observations.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            let result = &observation.result;
            let ExecutorContinuity::NotObservable { reason } = result.continuity;
            let _ = write!(
                output,
                "{{\"frame\":{},\"outcome\":\"{}\",\"score\":",
                observation.frame,
                result.outcome.as_str()
            );
            match result.outcome.score() {
                Some(score) => {
                    let _ = write!(output, "{score}");
                }
                None => output.push_str("null"),
            }
            if let ExecutorModelOutcome::Abstained {
                reason: abstention,
                receipt_outcome,
            } = result.outcome
            {
                let _ = write!(
                    output,
                    ",\"abstention\":\"{}\",\"receipt_outcome\":\"{}\"",
                    abstention.as_str(),
                    receipt_outcome.as_str()
                );
            }
            let _ = write!(
                output,
                ",\"result_digest\":\"{}\",\"invocation_receipt_digest\":\"{}\",\"invocation_receipt_object\":\"{}\",\"decode_receipt\":\"{}\",\"input_capture_root\":\"{}\",\"capsule_digest\":\"{}\",\"continuity\":{{\"not_observable\":\"{}\"}},\"reference_only\":{},\"supports_absence\":false}}",
                observation.result_digest,
                result.invocation_receipt_digest,
                result.invocation_receipt_object,
                result.decode_receipt_digest,
                result.input_capture_root,
                result.capsule_digest,
                reason.as_str(),
                result.reference_only,
            );
        }
        output.push_str("]}");
    }
}

struct StagedFrame {
    bytes: &'static [u8],
    decoded: DecodedRgb,
    source_digest: ContentDigest,
    capsule_digest: ContentDigest,
}

impl StagedFrame {
    fn binding(&self) -> ActivityFrameBinding<'_> {
        ActivityFrameBinding {
            pixels: self.decoded.pixels(),
            receipt: self.decoded.receipt(),
            source_digest: self.source_digest,
            capsule_digest: self.capsule_digest,
        }
    }
}

fn stage_checked(
    deployment: &mut ReferenceDeployment,
    staged: &mut Vec<ContentDigest>,
    bytes: &[u8],
    expected: ContentDigest,
    what: &str,
) -> Result<(), ScenarioError> {
    let digest = deployment.stage_payload(bytes)?;
    if digest != expected {
        return Err(ScenarioError::Reference(format!(
            "digest mismatch on {what}"
        )));
    }
    staged.push(digest);
    Ok(())
}

/// Stages, decodes and scores the recording; returns the observations for the policy.
pub fn gather(
    deployment: &mut ReferenceDeployment,
    staged: &mut Vec<ContentDigest>,
    interval: CaptureInterval,
    options: FileActivityOptions,
) -> Result<(Vec<ReferenceModelObservation>, FileActivityReport), ScenarioError> {
    let reference_error = |e: &dyn std::fmt::Display| ScenarioError::Reference(e.to_string());
    let sensor_id = SensorId::parse(format!("sensor:{FILE_SENSOR}"))?;
    let mut frames = Vec::with_capacity(FRAMES.len());
    for (sequence, bytes) in FRAMES.iter().copied().enumerate() {
        let source_digest = deployment.stage_payload(bytes)?;
        staged.push(source_digest);
        // A file carries no capture clock: one wide estimated interval, never file mtime.
        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: CapsuleId::parse(format!("capsule:{FILE_SENSOR}:{sequence}"))?,
            sensor_id: sensor_id.clone(),
            stream_id: StreamId::parse(format!("stream:{FILE_SENSOR}"))?,
            sequence: sequence as u64,
            capture: interval,
            receive_time: interval.latest,
            clock_basis: ClockBasis::Estimated,
            source: bytes,
            frame_count: 1,
            gap_before: false,
        })?;
        let capsule_digest = deployment.stage_payload(&capsule.canonical_bytes())?;
        staged.push(capsule_digest);
        let decoded = decode_rgb(
            bytes,
            source_digest.bytes(),
            ComponentInterpretation::Grayscale,
            RgbDecodeLimits::default(),
            &mut DecodeBudget::new(10_000_000),
        )
        .map_err(|e| reference_error(&e))?;
        let receipt_bytes = rgb_decode_receipt_bytes(&decoded.receipt());
        let receipt_digest = ContentDigest::sha256(&receipt_bytes);
        stage_checked(
            deployment,
            staged,
            &receipt_bytes,
            receipt_digest,
            "decode receipt",
        )?;
        frames.push(StagedFrame {
            bytes,
            decoded,
            source_digest,
            capsule_digest,
        });
    }
    let reference = frames
        .first()
        .ok_or(ScenarioError::Packet("empty recording"))?;
    let cx = ScalarExecCx::new();
    // The graph comes only from the committed, digest-pinned package, verified (archive,
    // license, spec, graph, weights) before any invocation; its archive bytes are retained.
    let model = ActivityExecutorModel::load_committed(&cx).map_err(|e| reference_error(&e))?;
    let package_sha256 = model.package().archive_digest();
    stage_checked(
        deployment,
        staged,
        ACTIVITY_PACKAGE_V1,
        package_sha256,
        "activity model package",
    )?;
    let mut observations = Vec::new();
    let mut reported = Vec::new();
    for (frame, staged_frame) in frames.iter().enumerate().skip(1) {
        let budget = if options.starve_frame == Some(frame) {
            ExecBudget::new(1, 1)
        } else {
            ExecBudget::new(EXECUTOR_MACS, EXECUTOR_BYTES)
        };
        let (result, receipt) = model
            .invoke(
                &sensor_id,
                staged_frame.binding(),
                reference.binding(),
                &options.policy,
                budget,
                &format!("job:lab:file-activity:{frame}"),
                &cx,
            )
            .map_err(|e| reference_error(&e))?;
        if staged_frame.source_digest != ContentDigest::sha256(staged_frame.bytes) {
            return Err(ScenarioError::Reference(
                "frame custody mismatch".to_owned(),
            ));
        }
        stage_checked(
            deployment,
            staged,
            receipt.to_json_canonical().as_bytes(),
            result.invocation_receipt_object,
            "model invocation receipt",
        )?;
        let result_digest = result.object_digest();
        stage_checked(
            deployment,
            staged,
            &result.canonical_bytes(),
            result_digest,
            "executor model result",
        )?;
        observations.push(ReferenceModelObservation::new(
            result.clone(),
            FILE_FAILURE_DOMAIN,
            interval,
        )?);
        reported.push(FileActivityObservation {
            frame,
            result,
            result_digest,
        });
    }
    Ok((
        observations,
        FileActivityReport {
            model_digest: model.digest(),
            package_sha256,
            model_package_root: model.package().manifest_digest(),
            policy: options.policy,
            reference_decode_receipt: ContentDigest::sha256(&rgb_decode_receipt_bytes(
                &reference.decoded.receipt(),
            )),
            observations: reported,
        },
    ))
}
