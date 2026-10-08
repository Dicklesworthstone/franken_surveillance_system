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
    CanonicalDecode, CanonicalDecoder, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis,
    ContentDigest, SensorCapsule, SensorId, SensorSourceBytesSpec, StreamId,
};
use fss_reference::executor_activity::{
    ACTIVITY_MODEL_GENERATION, ActivityExecutorModel, ActivityFrameBinding,
    ActivityThresholdPolicy, ExecutorContinuity, ExecutorModelOutcome, ExecutorModelResult,
    open_retained_executor_result, retain_executor_result, rgb_decode_receipt_bytes,
};
use fss_reference::executor_activity_package::ACTIVITY_PACKAGE_V1;
use fss_reference::{
    ExecBudget, ReferenceDeployment, ReferenceModelObservation, ReplayCx, ScalarExecCx,
};

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

/// The identities of one staged frame: its source bytes and its canonical sensor capsule, both
/// already in the deployment's spool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedSource {
    /// Spool digest of the frame's source bytes.
    pub source_digest: ContentDigest,
    /// Spool digest of the frame's canonical capsule bytes.
    pub capsule_digest: ContentDigest,
}

/// A frame read back from custody: its capsule decoded from the retained capsule bytes and its
/// pixels decoded from the retained source bytes, never from the caller's copy.
struct CustodyFrame {
    decoded: DecodedRgb,
    source_digest: ContentDigest,
    capsule: SensorCapsule,
}

impl CustodyFrame {
    fn binding(&self) -> ActivityFrameBinding<'_> {
        ActivityFrameBinding {
            pixels: self.decoded.pixels(),
            receipt: self.decoded.receipt(),
            source_digest: self.source_digest,
            capsule: &self.capsule,
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

/// Reads one staged object back from the deployment spool and re-hashes it: the bytes the lab
/// decodes are the retained bytes, so damage after staging is refused here, before any decode.
fn read_custody(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    what: &str,
) -> Result<Vec<u8>, ScenarioError> {
    let bytes =
        deployment.publisher().spool().read(digest).map_err(|e| {
            ScenarioError::Reference(format!("{what} unreadable from custody: {e}"))
        })?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(ScenarioError::Reference(format!(
            "{what} custody digest mismatch"
        )));
    }
    Ok(bytes)
}

/// Stages the recording: each frame's source bytes and its sensor capsule. A file carries no
/// capture clock, so every capsule has one wide estimated interval, never file mtime.
pub fn stage_recording(
    deployment: &mut ReferenceDeployment,
    staged: &mut Vec<ContentDigest>,
    interval: CaptureInterval,
) -> Result<Vec<StagedSource>, ScenarioError> {
    let sensor_id = SensorId::parse(format!("sensor:{FILE_SENSOR}"))?;
    let mut sources = Vec::with_capacity(FRAMES.len());
    for (sequence, bytes) in FRAMES.iter().copied().enumerate() {
        let source_digest = deployment.stage_payload(bytes)?;
        staged.push(source_digest);
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
        sources.push(StagedSource {
            source_digest,
            capsule_digest,
        });
    }
    Ok(sources)
}

/// Re-reads every staged frame from the spool (re-hashed), decodes the retained capsule and the
/// retained source bytes, scores every frame after the first against the first, and retains each
/// executor result with its invocation receipt as ledgered objects
/// ([`retain_executor_result`]). Returns the observations for the policy.
pub fn evaluate_recording(
    deployment: &mut ReferenceDeployment,
    staged: &mut Vec<ContentDigest>,
    sources: &[StagedSource],
    interval: CaptureInterval,
    options: FileActivityOptions,
    cx: &ReplayCx,
) -> Result<(Vec<ReferenceModelObservation>, FileActivityReport), ScenarioError> {
    let reference_error = |e: &dyn std::fmt::Display| ScenarioError::Reference(e.to_string());
    let sensor_id = SensorId::parse(format!("sensor:{FILE_SENSOR}"))?;
    let mut frames = Vec::with_capacity(sources.len());
    for source in sources {
        let bytes = read_custody(deployment, source.source_digest, "frame source")?;
        let capsule_bytes = read_custody(deployment, source.capsule_digest, "frame capsule")?;
        let mut decoder = CanonicalDecoder::new(&capsule_bytes);
        let capsule = SensorCapsule::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        if capsule.source_digest != source.source_digest || capsule.sensor_id != sensor_id {
            return Err(ScenarioError::Reference(
                "capsule does not name its staged frame".to_owned(),
            ));
        }
        let decoded = decode_rgb(
            &bytes,
            source.source_digest.bytes(),
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
        frames.push(CustodyFrame {
            decoded,
            source_digest: source.source_digest,
            capsule,
        });
    }
    let reference = frames
        .first()
        .ok_or(ScenarioError::Packet("empty recording"))?;
    let exec_cx = ScalarExecCx::new();
    // The graph comes only from the committed, digest-pinned package, verified (archive,
    // license, spec, graph, weights) before any invocation; its archive bytes are retained.
    let model = ActivityExecutorModel::load_committed(&exec_cx).map_err(|e| reference_error(&e))?;
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
    for (frame, custody_frame) in frames.iter().enumerate().skip(1) {
        cx.checkpoint("file_activity:invoke")
            .map_err(|e| reference_error(&e))?;
        let budget = if options.starve_frame == Some(frame) {
            ExecBudget::new(1, 1)
        } else {
            ExecBudget::new(EXECUTOR_MACS, EXECUTOR_BYTES)
        };
        let (result, receipt) = model
            .invoke(
                &sensor_id,
                custody_frame.binding(),
                reference.binding(),
                &options.policy,
                budget,
                &format!("job:lab:file-activity:{frame}"),
                &exec_cx,
            )
            .map_err(|e| reference_error(&e))?;
        // The result and its receipt are ledgered (fss-2h5zq.51): reachable from a committed
        // root and an `executor_model_result` / `model_invocation_receipt` batch.
        let retained = retain_executor_result(deployment, &result, &receipt, interval, cx)
            .map_err(|e| reference_error(&e))?;
        staged.push(result.invocation_receipt_object);
        staged.push(retained.result_digest);
        observations.push(ReferenceModelObservation::new(
            result.clone(),
            FILE_FAILURE_DOMAIN,
            interval,
        )?);
        reported.push(FileActivityObservation {
            frame,
            result,
            result_digest: retained.result_digest,
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

/// Stages, re-reads, decodes and scores the recording; returns the observations for the policy.
pub fn gather(
    deployment: &mut ReferenceDeployment,
    staged: &mut Vec<ContentDigest>,
    interval: CaptureInterval,
    options: FileActivityOptions,
    cx: &ReplayCx,
) -> Result<(Vec<ReferenceModelObservation>, FileActivityReport), ScenarioError> {
    let sources = stage_recording(deployment, staged, interval)?;
    evaluate_recording(deployment, staged, &sources, interval, options, cx)
}

/// After a restart: every reported observation's result and receipt read back from the reopened
/// deployment's ledger and spool, equal to what the run reported.
pub fn verify_retained(
    root: &std::path::Path,
    report: &FileActivityReport,
    cx: &ReplayCx,
) -> Result<(), ScenarioError> {
    let reopened = ReferenceDeployment::reopen(root, "site:lab", cx)?;
    for observation in &report.observations {
        let retained = open_retained_executor_result(&reopened, observation.result_digest, cx)
            .map_err(|e| ScenarioError::Reference(e.to_string()))?;
        if retained.result != observation.result {
            return Err(ScenarioError::Reference(format!(
                "retained executor result of frame {} differs after restart",
                observation.frame
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{ScenarioKind, make_cx};
    use fss_core::TimestampNs;

    struct Root(std::path::PathBuf);

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Review finding (2026-10-08, fss-2h5zq.50): the lab staged the frame bytes and then decoded
    /// its own in-memory copy, so a staged object damaged in the spool was never noticed. The
    /// lab now decodes only bytes re-read (and re-hashed) from custody: a frame tampered on disk
    /// after staging is refused before decode, and nothing is scored or retained for it.
    #[test]
    fn a_frame_tampered_in_the_spool_after_staging_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root(std::env::temp_dir().join(format!(
            "fss-lab-file-activity-tamper-{}",
            std::process::id()
        )));
        let cx = make_cx(ScenarioKind::FileActivity)?;
        let mut deployment = ReferenceDeployment::open(&root.0, "site:lab", &cx)?;
        let interval = CaptureInterval::new(TimestampNs(0), TimestampNs(5_000_000_000))?;
        let mut staged = Vec::new();
        let sources = stage_recording(&mut deployment, &mut staged, interval)?;
        // Frame 2 (the gradient) is the only frame whose source bytes no other frame shares.
        let target = sources.get(2).ok_or("no frame 2")?.source_digest;
        let path = deployment.publisher().spool().object_path(target);
        let mut bytes = std::fs::read(&path)?;
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0x40;
        std::fs::write(&path, bytes)?;
        let ledger_before = deployment.current_anchor().commit_sequence;
        let outcome = evaluate_recording(
            &mut deployment,
            &mut staged,
            &sources,
            interval,
            FileActivityOptions::reference()?,
            &cx,
        );
        match outcome {
            Err(ScenarioError::Reference(message)) => {
                assert!(message.contains("frame source"), "{message}");
            }
            other => return Err(format!("tampered frame was not refused: {other:?}").into()),
        }
        // Refused before any invocation: no result or receipt was retained.
        assert_eq!(deployment.current_anchor().commit_sequence, ledger_before);
        Ok(())
    }

    /// The untampered control: the same staged recording re-read from custody scores and
    /// retains both evaluated frames.
    #[test]
    fn an_untampered_staged_recording_is_scored_from_custody()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Root(std::env::temp_dir().join(format!(
            "fss-lab-file-activity-custody-{}",
            std::process::id()
        )));
        let cx = make_cx(ScenarioKind::FileActivity)?;
        let mut deployment = ReferenceDeployment::open(&root.0, "site:lab", &cx)?;
        let interval = CaptureInterval::new(TimestampNs(0), TimestampNs(5_000_000_000))?;
        let mut staged = Vec::new();
        let sources = stage_recording(&mut deployment, &mut staged, interval)?;
        let (observations, report) = evaluate_recording(
            &mut deployment,
            &mut staged,
            &sources,
            interval,
            FileActivityOptions::reference()?,
            &cx,
        )?;
        assert_eq!(observations.len(), 2);
        for (observation, source) in report.observations.iter().zip(&sources[1..]) {
            assert_eq!(observation.result.input_capture_root, source.source_digest);
            assert_eq!(observation.result.capsule_digest, source.capsule_digest);
            let retained =
                open_retained_executor_result(&deployment, observation.result_digest, &cx)?;
            assert_eq!(retained.result, observation.result);
        }
        Ok(())
    }
}
