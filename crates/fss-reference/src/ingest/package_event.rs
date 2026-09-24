#![forbid(unsafe_code)]
//! Retained package detections -> one tracked label -> unresolved recorded events.
//!
//! The luma recorded-event path ([`super::recorded_event`]) consumes retained model runs of the
//! frame-luma model format. A verified RGB detector package (`fss-infer package-detect`) produces a
//! `fss.package_detection_report.v1` instead, so this module is the equivalent path for it:
//!
//! 1. [`retain_package_detection`] retains one completed package detection as cognition-plane
//!    evidence: the exact report JSON plus a canonical record of every frame (capsule, capture,
//!    inference identity, output and head-report digests, every surviving detection), root-last,
//!    with one `package_detection_record` ledger delta. It is written only by the deployment's own
//!    computation (`fss-infer package-detect --retain yes`), never from an operator-supplied file.
//! 2. [`PackageAnalysisReport::read`] reopens it from custody (no model execution) and tracks one
//!    explicitly chosen label with the same constant-velocity Kalman tracker the watch pipeline
//!    uses, producing a canonical, self-verifying report (`fss-event report --package-report`).
//! 3. [`PackageEventProposal`] prepares and, with the exact approved proposal digest, publishes
//!    one confirmed track as an `Unclassified`, `Indeterminate`, abstaining, single-sensor event
//!    through the deployment's guarded event publisher (`fss-event prepare` / `publish`).
//!
//! Detector scores are uncalibrated; associated detections are supporting evidence in the one
//! sensor's failure domain, so an event can never be corroborated by a detector, and no alert or
//! other effect is authorized. A frame without a detection is not evidence of absence.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_core::event::EventDecodeError;
use fss_core::{
    BatchId, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError, DecisionPath, EventEvidence, EventHypothesis, EventId, EventKind, EventState,
    EvidenceClass, EvidenceDelta, EvidenceEdgeRelation, LedgerAnchor, ObjectId, Plane,
    ProbabilityInterval, TimestampNs,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};
use fss_publication::{LocalPublicationError, SlotName};

use super::detector_cascade::iou_ppm;
use super::package_detect::{MAX_PACKAGE_DETECT_FRAMES, PackageDetectReport};
use super::rgb_package::RgbDetectorPackage;
use super::tracker::{
    Detection, MultiObjectTracker, TrackStatus, TrackerConfig, TrackerError, TrackerLimits,
    TrackerStepError,
};
use crate::{
    ReferenceDeployment, ReferenceError, ReferencePolicyAction, ReferencePolicyDecision, ReplayCx,
};

/// Canonical record of one retained package detection.
pub const PACKAGE_DETECTION_RECORD_DOMAIN: &str = "fss.package_detection_record.v1";
/// Canonical package analysis report consumed by `fss-event prepare`/`publish`.
pub const PACKAGE_ANALYSIS_REPORT_DOMAIN: &str = "fss.package_analysis_report.v1";
/// Ledger delta family of a retained package detection.
pub const PACKAGE_DETECTION_FAMILY: &str = "package_detection_record";
/// Largest canonical package analysis report.
pub const MAX_PACKAGE_ANALYSIS_BYTES: usize = 4 * 1024 * 1024;
/// Boundary after provenance retention, before event authority.
pub const STAGE_PACKAGE_EVENT_COMMIT: &str = "package_event:commit";

const RECORD_MAGIC: &[u8] = b"FSSPDET1";
const REPORT_MAGIC: &[u8] = b"FSSPANR1";
const OBSERVATION_DOMAIN: &str = "fss.package_event_observation.v1";
const PROVENANCE_DOMAIN: &str = "fss.package_event_provenance.v1";
const PROPOSAL_DOMAIN: &str = "fss.package_event_proposal.v1";
const TRACK_DOMAIN: &str = "fss.package_event_track.v1";
const POLICY: &[u8] = b"fss.package_event_policy.v1:retained-package-detections:single-label:\
kalman-global-iou:uncalibrated-scores:unclassified:indeterminate:hold:single-sensor";
const MAX_TEXT: usize = 512;
const MAX_LABELS: usize = 256;
const MAX_DETECTIONS: usize = 256;
// Kalman noise is fixed policy (bound through POLICY), exactly as in the watch pipeline.
const PROCESS_NOISE: f64 = 1.0;
const MEASUREMENT_NOISE: f64 = 1.0;
const UNCERTAINTY: &str = "Uncalibrated detector-package proposals of one label, associated by \
a Kalman tracker on one sensor; never corroborated; capture bounds are evidence windows.";
const ABSTENTION: &str = "Retain and investigate. No presence, identity, class, absence, \
corroboration or alert decision is authorized by a single-sensor detector track.";

/// Typed refusal; no partial record, report, proposal or event is returned.
#[derive(Debug)]
pub enum PackageEventError {
    /// Label, tracking policy or report bytes outside this operation's contract.
    InvalidRequest(&'static str),
    /// The deployment retains no package detection with this report digest.
    Unavailable,
    /// Retained custody, report bytes or rebuilt provenance disagree.
    Mismatch,
    /// A hard frame, detection, track or byte bound was reached.
    Limit,
    /// The selected track does not exist or was never confirmed in this report.
    TrackUnavailable,
    /// The approval names another proposal than the one freshly prepared.
    StaleProposal,
    /// An event with this identity exists with different content.
    Conflict,
    /// Owner cancellation; committed provenance can remain, but no success is invented.
    Cancelled,
    /// Tracker configuration or step refusal.
    Tracker(String),
    /// Shared canonical validation failed.
    Contract(ContractError),
    /// Event schema refusal.
    Event(Box<EventDecodeError>),
    /// Guarded deployment publication failed.
    Reference(Box<ReferenceError>),
    /// Object graph construction failed.
    Object(ObjectError),
    /// Root-last publication failed.
    Publication(Box<LocalPublicationError>),
    /// Retained custody could not be read or verified.
    Spool(SpoolError),
}
impl PackageEventError {
    /// Registered stable identity (registries/ERRORS.md).
    #[must_use]
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) | Self::Tracker(_) => "ERR-PACKAGE-EVENT-REQUEST-001",
            Self::Unavailable => "ERR-PACKAGE-EVENT-UNAVAILABLE-001",
            Self::Mismatch => "ERR-PACKAGE-EVENT-MISMATCH-001",
            Self::TrackUnavailable => "ERR-PACKAGE-EVENT-TRACK-001",
            Self::StaleProposal => "ERR-PACKAGE-EVENT-APPROVAL-STALE-001",
            Self::Conflict => "ERR-IDEMPOTENCY-CONFLICT-001",
            Self::Cancelled => "ERR-PACKAGE-EVENT-CANCELLED-001",
            _ => "ERR-PACKAGE-EVENT-001",
        }
    }
}
impl fmt::Display for PackageEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(why) => write!(f, "package event request invalid: {why}"),
            Self::Unavailable => f.write_str(
                "no retained package detection with this report digest (run fss-infer package-detect --retain yes)",
            ),
            Self::Mismatch => f.write_str("package detection custody or report mismatch"),
            Self::Limit => f.write_str("package event bound exceeded"),
            Self::TrackUnavailable => {
                f.write_str("selected track is absent or was never confirmed in this report")
            }
            Self::StaleProposal => {
                f.write_str("package event proposal changed; prepare and review again")
            }
            Self::Conflict => f.write_str("a different event already holds this track identity"),
            Self::Cancelled => f.write_str("package event cancelled"),
            Self::Tracker(why) => write!(f, "package event tracker refused: {why}"),
            Self::Contract(e) => write!(f, "package event contract: {e}"),
            Self::Event(e) => write!(f, "package event schema: {e}"),
            Self::Reference(e) => write!(f, "package event deployment: {e}"),
            Self::Object(e) => write!(f, "package event manifest: {e}"),
            Self::Publication(e) => write!(f, "package event publication: {e}"),
            Self::Spool(e) => write!(f, "package event custody: {e}"),
        }
    }
}
impl std::error::Error for PackageEventError {}
macro_rules! conversion {
    ($source:ty, $variant:ident) => {
        impl From<$source> for PackageEventError {
            fn from(error: $source) -> Self {
                Self::$variant(error.into())
            }
        }
    };
}
conversion!(ContractError, Contract);
conversion!(EventDecodeError, Event);
conversion!(ReferenceError, Reference);
conversion!(ObjectError, Object);
conversion!(LocalPublicationError, Publication);
conversion!(SpoolError, Spool);
impl From<TrackerError> for PackageEventError {
    fn from(error: TrackerError) -> Self {
        Self::Tracker(error.to_string())
    }
}
impl From<TrackerStepError> for PackageEventError {
    fn from(error: TrackerStepError) -> Self {
        match error {
            TrackerStepError::Limit => Self::Limit,
            other => Self::Tracker(other.to_string()),
        }
    }
}
type Result<T> = std::result::Result<T, PackageEventError>;

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| PackageEventError::Cancelled)
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn text(d: &mut CanonicalDecoder<'_>) -> Result<String> {
    let value = d.text()?;
    if value.len() > MAX_TEXT {
        return Err(PackageEventError::Limit);
    }
    Ok(value.to_owned())
}
fn count(d: &mut CanonicalDecoder<'_>, ceiling: usize) -> Result<usize> {
    let n = usize::try_from(d.u64()?).map_err(|_| PackageEventError::Limit)?;
    if n > ceiling {
        return Err(PackageEventError::Limit);
    }
    Ok(n)
}
fn read_verified(deployment: &ReferenceDeployment, digest: ContentDigest) -> Result<Vec<u8>> {
    let bytes = deployment.publisher().spool().read(digest)?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(PackageEventError::Mismatch);
    }
    Ok(bytes)
}

/// One surviving detection of a retained frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordDetection {
    /// Head row.
    pub row: u64,
    /// Label index.
    pub class_index: u64,
    /// F32 score bits (uncalibrated).
    pub score_bits: u32,
    /// Source-grid XYXY in 1/256 pixels.
    pub bounds: [u32; 4],
    /// Clipped to the image.
    pub clipped: bool,
}

/// One retained frame of a package detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordFrame {
    /// Retained segment.
    pub segment: u64,
    /// Source-capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Recording sensor.
    pub sensor_id: String,
    /// Conservative capture interval.
    pub capture: CaptureInterval,
    /// Coded dimensions.
    pub dimensions: [u32; 2],
    /// Colour path (`jpeg_rgb` or `ycbcr420_bt601_limited_rgb`).
    pub color: String,
    /// Inference identity.
    pub inference_identity: ContentDigest,
    /// Output tensor digest.
    pub output_digest: ContentDigest,
    /// Head projection report digest.
    pub detection_report_digest: ContentDigest,
    /// Every NMS survivor, in report order.
    pub detections: Vec<RecordDetection>,
}

/// Canonical record of one completed package detection (the retained ledger payload).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageDetectionRecord {
    /// SHA-256 of the exact report JSON.
    pub report_digest: ContentDigest,
    /// Package archive digest.
    pub package_digest: ContentDigest,
    /// Package manifest digest.
    pub manifest_digest: ContentDigest,
    /// Model id.
    pub model_id: String,
    /// Model generation.
    pub generation: String,
    /// Built model digest.
    pub model_digest: ContentDigest,
    /// Graph artifact digest.
    pub graph_digest: ContentDigest,
    /// Applied head contract digest.
    pub contract_digest: ContentDigest,
    /// Exact import.
    pub import_identity: ContentDigest,
    /// Import root.
    pub import_root: ContentDigest,
    /// Retained media format.
    pub media_format: String,
    /// First segment of the range.
    pub first_segment: u64,
    /// Requested segment count.
    pub segment_count: u64,
    /// Applied threshold.
    pub minimum_score_ppm: u32,
    /// Ordered label vocabulary.
    pub labels: Vec<String>,
    /// Completed frames.
    pub frames: Vec<RecordFrame>,
}

impl PackageDetectionRecord {
    /// Builds the record of a completed report produced with `package`.
    pub fn from_report(package: &RgbDetectorPackage, report: &PackageDetectReport) -> Result<Self> {
        if report.frames.is_empty() || report.frames.len() > MAX_PACKAGE_DETECT_FRAMES {
            return Err(PackageEventError::Limit);
        }
        let mut frames = Vec::with_capacity(report.frames.len());
        for frame in &report.frames {
            let detections = frame.detections.detections();
            if detections.len() > MAX_DETECTIONS {
                return Err(PackageEventError::Limit);
            }
            frames.push(RecordFrame {
                segment: frame.segment as u64,
                capsule_digest: frame.capsule_digest,
                sensor_id: frame.capsule.sensor_id.as_str().to_owned(),
                capture: frame.capsule.capture,
                dimensions: frame.dimensions,
                color: frame.color.to_owned(),
                inference_identity: frame.inference.identity(),
                output_digest: frame.inference.output_digest(),
                detection_report_digest: frame.detections.digest(),
                detections: detections
                    .iter()
                    .map(|d| RecordDetection {
                        row: d.row() as u64,
                        class_index: d.class_index() as u64,
                        score_bits: d.score().to_bits(),
                        bounds: d.bounds(),
                        clipped: d.clipped(),
                    })
                    .collect(),
            });
        }
        Ok(Self {
            report_digest: report.digest,
            package_digest: package.archive_digest(),
            manifest_digest: package.manifest_digest(),
            model_id: package.manifest().model_id().as_str().to_owned(),
            generation: package.manifest().generation().as_str().to_owned(),
            model_digest: package.model().digest(),
            graph_digest: package.graph_digest(),
            contract_digest: report.contract,
            import_identity: report.import_identity,
            import_root: report.import_root,
            media_format: report.media_format.clone(),
            first_segment: report.first_segment as u64,
            segment_count: report.segment_count as u64,
            minimum_score_ppm: report.minimum_score_ppm,
            labels: package.contract().spec().labels.clone(),
            frames,
        })
    }

    /// Canonical bytes (the ledger payload).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = CanonicalEncoder::new();
        e.bytes(RECORD_MAGIC);
        e.u32(1);
        e.text(PACKAGE_DETECTION_RECORD_DOMAIN);
        for digest in [
            self.report_digest,
            self.package_digest,
            self.manifest_digest,
        ] {
            e.digest(digest);
        }
        e.text(&self.model_id);
        e.text(&self.generation);
        for digest in [
            self.model_digest,
            self.graph_digest,
            self.contract_digest,
            self.import_identity,
            self.import_root,
        ] {
            e.digest(digest);
        }
        e.text(&self.media_format);
        e.u64(self.first_segment);
        e.u64(self.segment_count);
        e.u32(self.minimum_score_ppm);
        e.u64(self.labels.len() as u64);
        for label in &self.labels {
            e.text(label);
        }
        e.u64(self.frames.len() as u64);
        for frame in &self.frames {
            e.u64(frame.segment);
            e.digest(frame.capsule_digest);
            e.text(&frame.sensor_id);
            e.i128(frame.capture.earliest.0);
            e.i128(frame.capture.latest.0);
            e.u32(frame.dimensions[0]);
            e.u32(frame.dimensions[1]);
            e.text(&frame.color);
            e.digest(frame.inference_identity);
            e.digest(frame.output_digest);
            e.digest(frame.detection_report_digest);
            e.u64(frame.detections.len() as u64);
            for d in &frame.detections {
                e.u64(d.row);
                e.u64(d.class_index);
                e.u32(d.score_bits);
                for value in d.bounds {
                    e.u32(value);
                }
                e.bool(d.clipped);
            }
        }
        Ok(e.finish_checked()?)
    }

    /// Strict canonical decode with allocation ceilings.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != RECORD_MAGIC
            || d.u32()? != 1
            || d.text()? != PACKAGE_DETECTION_RECORD_DOMAIN
        {
            return Err(PackageEventError::Mismatch);
        }
        let report_digest = d.digest()?;
        let package_digest = d.digest()?;
        let manifest_digest = d.digest()?;
        let model_id = text(&mut d)?;
        let generation = text(&mut d)?;
        let model_digest = d.digest()?;
        let graph_digest = d.digest()?;
        let contract_digest = d.digest()?;
        let import_identity = d.digest()?;
        let import_root = d.digest()?;
        let media_format = text(&mut d)?;
        let first_segment = d.u64()?;
        let segment_count = d.u64()?;
        let minimum_score_ppm = d.u32()?;
        let n = count(&mut d, MAX_LABELS)?;
        let mut labels = Vec::with_capacity(n);
        for _ in 0..n {
            labels.push(text(&mut d)?);
        }
        let n = count(&mut d, MAX_PACKAGE_DETECT_FRAMES)?;
        let mut frames = Vec::with_capacity(n);
        for _ in 0..n {
            let segment = d.u64()?;
            let capsule_digest = d.digest()?;
            let sensor_id = text(&mut d)?;
            let capture = CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?;
            let dimensions = [d.u32()?, d.u32()?];
            let color = text(&mut d)?;
            let inference_identity = d.digest()?;
            let output_digest = d.digest()?;
            let detection_report_digest = d.digest()?;
            let m = count(&mut d, MAX_DETECTIONS)?;
            let mut detections = Vec::with_capacity(m);
            for _ in 0..m {
                detections.push(RecordDetection {
                    row: d.u64()?,
                    class_index: d.u64()?,
                    score_bits: d.u32()?,
                    bounds: [d.u32()?, d.u32()?, d.u32()?, d.u32()?],
                    clipped: d.bool()?,
                });
            }
            frames.push(RecordFrame {
                segment,
                capsule_digest,
                sensor_id,
                capture,
                dimensions,
                color,
                inference_identity,
                output_digest,
                detection_report_digest,
                detections,
            });
        }
        d.ensure_finished()?;
        let record = Self {
            report_digest,
            package_digest,
            manifest_digest,
            model_id,
            generation,
            model_digest,
            graph_digest,
            contract_digest,
            import_identity,
            import_root,
            media_format,
            first_segment,
            segment_count,
            minimum_score_ppm,
            labels,
            frames,
        };
        if record.frames.is_empty() || record.encode()? != bytes {
            return Err(PackageEventError::Mismatch);
        }
        Ok(record)
    }

    fn slot(&self) -> Result<SlotName> {
        SlotName::parse(&format!("pd-{}", hex(self.report_digest)))
            .map_err(|_| PackageEventError::Mismatch)
    }
    fn batch_id(&self) -> Result<BatchId> {
        Ok(BatchId::parse(format!(
            "batch:package-detection:{}",
            hex(self.report_digest)
        ))?)
    }
    fn validity(&self) -> Result<CaptureInterval> {
        let first = self.frames.first().ok_or(PackageEventError::Limit)?.capture;
        let mut interval = first;
        for frame in &self.frames {
            interval = CaptureInterval::new(
                interval.earliest.min(frame.capture.earliest),
                interval.latest.max(frame.capture.latest),
            )?;
        }
        Ok(interval)
    }
    fn manifest(&self, record_digest: ContentDigest) -> Result<ObjectManifest> {
        let mut children = BTreeSet::from([self.report_digest, self.import_root]);
        children.extend(self.frames.iter().map(|f| f.capsule_digest));
        children.remove(&record_digest);
        Ok(ObjectManifest::new(
            self.slot()?.as_str(),
            children,
            Some(record_digest),
        )?)
    }
    fn delta(&self, record_digest: ContentDigest, root: ContentDigest) -> Result<EvidenceDelta> {
        let id = hex(self.report_digest);
        Ok(EvidenceDelta {
            delta_id: format!("delta:package-detection:{id}"),
            family: PACKAGE_DETECTION_FAMILY.to_owned(),
            object_id: ObjectId::parse(format!("object:package-detection:{id}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: self.validity()?,
            plane: Plane::Cognition,
            payload_digest: record_digest,
            witness_digest: Some(root),
            operation_id: None,
        })
    }
}

/// Whether a retention call wrote the record or found it already retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionStatus {
    /// Written by this call.
    Retained,
    /// An identical record was already retained; nothing was written.
    AlreadyRetained,
}
impl RetentionStatus {
    /// Stable spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Retained => "retained",
            Self::AlreadyRetained => "already_retained",
        }
    }
}

/// A package detection verified from retained custody.
#[derive(Clone, Debug)]
pub struct RetainedPackageDetection {
    record: PackageDetectionRecord,
    record_digest: ContentDigest,
    root: ContentDigest,
    anchor: LedgerAnchor,
    status: RetentionStatus,
}
impl RetainedPackageDetection {
    /// Reopens and verifies a retained package detection by its report digest.
    pub fn open(
        deployment: &ReferenceDeployment,
        report_digest: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "package_event:open")?;
        let target = BatchId::parse(format!("batch:package-detection:{}", hex(report_digest)))?;
        let batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|b| b.batch_id == target)
            .ok_or(PackageEventError::Unavailable)?;
        let [delta] = batch.deltas.as_slice() else {
            return Err(PackageEventError::Mismatch);
        };
        let bytes = read_verified(deployment, delta.payload_digest)?;
        let record = PackageDetectionRecord::decode(&bytes)?;
        if record.report_digest != report_digest {
            return Err(PackageEventError::Mismatch);
        }
        let manifest = record.manifest(delta.payload_digest)?;
        let root = manifest.root();
        let mut children = manifest.children().to_vec();
        children.push(root);
        children.sort_unstable();
        children.dedup();
        if *delta != record.delta(delta.payload_digest, root)?
            || batch.children != children
            || deployment
                .publisher()
                .root(&record.slot()?)
                .is_none_or(|r| r.root != root)
            || read_verified(deployment, root)? != manifest.canonical_bytes()
        {
            return Err(PackageEventError::Mismatch);
        }
        read_verified(deployment, record.report_digest)?;
        Ok(Self {
            record,
            record_digest: delta.payload_digest,
            root,
            anchor: batch.new_anchor.clone(),
            status: RetentionStatus::AlreadyRetained,
        })
    }
    /// Verified record.
    #[must_use]
    pub fn record(&self) -> &PackageDetectionRecord {
        &self.record
    }
    /// Record (ledger payload) digest.
    #[must_use]
    pub fn record_digest(&self) -> ContentDigest {
        self.record_digest
    }
    /// Retained root.
    #[must_use]
    pub fn root(&self) -> ContentDigest {
        self.root
    }
    /// Anchor of the retention batch.
    #[must_use]
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Whether this call retained it.
    #[must_use]
    pub fn status(&self) -> RetentionStatus {
        self.status
    }
}

/// Retains a completed package detection computed by this deployment (root-last, then one
/// `package_detection_record` delta). An exact rerun reports it as already retained.
pub fn retain_package_detection(
    deployment: &mut ReferenceDeployment,
    package: &RgbDetectorPackage,
    report: &PackageDetectReport,
    cx: &ReplayCx,
) -> Result<RetainedPackageDetection> {
    checkpoint(cx, "package_event:retain")?;
    if report.digest != ContentDigest::sha256(report.json.as_bytes())
        || report
            .frames
            .iter()
            .any(|f| f.detections.contract_digest() != report.contract)
    {
        return Err(PackageEventError::Mismatch);
    }
    let record = PackageDetectionRecord::from_report(package, report)?;
    let target = record.batch_id()?;
    if deployment
        .ledger()
        .batches()
        .iter()
        .any(|b| b.batch_id == target)
    {
        let existing = RetainedPackageDetection::open(deployment, record.report_digest, cx)?;
        if existing.record != record {
            return Err(PackageEventError::Mismatch);
        }
        return Ok(existing);
    }
    let bytes = record.encode()?;
    let record_digest = ContentDigest::sha256(&bytes);
    let manifest = record.manifest(record_digest)?;
    let slot = record.slot()?;
    let existing_root = deployment.publisher().root(&slot).map(|r| r.root);
    if existing_root.is_some_and(|root| root != manifest.root()) {
        return Err(PackageEventError::Mismatch);
    }
    for object in [report.json.as_bytes(), bytes.as_slice()] {
        checkpoint(cx, "package_event:stage")?;
        let digest = deployment.publisher_mut().stage_object(object)?;
        deployment.publisher_mut().verify_object(digest)?;
    }
    for digest in manifest.children() {
        checkpoint(cx, "package_event:closure")?;
        deployment.publisher_mut().verify_object(*digest)?;
    }
    if existing_root.is_none() {
        deployment
            .publisher_mut()
            .stage_manifest(&slot, &manifest)?;
    }
    deployment.publish_and_commit(&slot, &manifest, record.validity()?, cx)?;
    checkpoint(cx, "package_event:retain_commit")?;
    let delta = record.delta(record_digest, manifest.root())?;
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    let anchor = deployment.append_batch(record.batch_id()?, vec![delta], children, cx)?;
    cx.checkpoint_post_commit("package_event:retained");
    Ok(RetainedPackageDetection {
        root: manifest.root(),
        record,
        record_digest,
        anchor,
        status: RetentionStatus::Retained,
    })
}

/// Kalman/IoU tracking policy of a package analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageTrackingConfig {
    /// Consecutive hits before a track is confirmed.
    pub confirmation_hits: u32,
    /// Consecutive misses before a track is deleted.
    pub maximum_missed_frames: u32,
    /// Minimum predicted-box IoU for association, parts per million.
    pub minimum_iou_ppm: u32,
}
impl PackageTrackingConfig {
    fn tracker(&self) -> Result<TrackerConfig> {
        if self.minimum_iou_ppm > 1_000_000 {
            return Err(PackageEventError::InvalidRequest(
                "minimum IoU must be at most 1000000 ppm",
            ));
        }
        let config = TrackerConfig {
            min_hits: self.confirmation_hits,
            max_misses: self.maximum_missed_frames,
            iou_threshold: f64::from(self.minimum_iou_ppm) / 1_000_000.0,
            process_noise: PROCESS_NOISE,
            measurement_noise: MEASUREMENT_NOISE,
        };
        config.validate()?;
        Ok(config)
    }
}

/// One matched frame of a tracked label, with the detection it was associated with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageObservation {
    /// Retained segment.
    pub segment: u64,
    /// Source-capsule payload digest.
    pub capsule_digest: ContentDigest,
    /// Filtered track box `(cx, cy, w, h)` in pixels, rounded.
    pub track_box: [i64; 4],
    /// Best-IoU detection of the label `(row, score bits, bounds, IoU ppm)`, if any overlaps.
    pub detection: Option<(u64, u32, [u32; 4], u32)>,
}

/// One track of the chosen label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackageTrack {
    /// Deterministic identity (record, label, policy, tracker id); not a physical identity.
    pub identity: ContentDigest,
    /// Tracker-local id.
    pub track_id: u64,
    /// Whether the track was ever confirmed.
    pub confirmed: bool,
    /// Matched frames in order.
    pub observations: Vec<PackageObservation>,
}

/// Canonical, self-verifying analysis of one retained package detection for one label.
#[derive(Clone, Debug)]
pub struct PackageAnalysisReport {
    retained: RetainedPackageDetection,
    label: String,
    class_index: u64,
    config: PackageTrackingConfig,
    tracks: Vec<PackageTrack>,
    bytes: Vec<u8>,
    digest: ContentDigest,
}

fn rounded(value: f64) -> i64 {
    // Finite by tracker admission; bounded by the image size.
    value.round() as i64
}

impl PackageAnalysisReport {
    /// Whether `bytes` are (the start of) a canonical package analysis report.
    #[must_use]
    pub fn is_package_report(bytes: &[u8]) -> bool {
        let mut d = CanonicalDecoder::new(bytes);
        matches!(d.bytes(), Ok(magic) if magic == REPORT_MAGIC)
    }

    /// Reopens the retained detection (no model execution) and tracks `label`.
    pub fn read(
        deployment: &ReferenceDeployment,
        report_digest: ContentDigest,
        label: &str,
        config: PackageTrackingConfig,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "package_event:analyze")?;
        let tracker_config = config.tracker()?;
        let retained = RetainedPackageDetection::open(deployment, report_digest, cx)?;
        let record = retained.record();
        let class_index = record.labels.iter().position(|l| l == label).ok_or(
            PackageEventError::InvalidRequest("label is not in the package vocabulary"),
        )? as u64;
        let mut tracker = MultiObjectTracker::new(tracker_config)?;
        let mut tracks: BTreeMap<u64, PackageTrack> = BTreeMap::new();
        for frame in &record.frames {
            checkpoint(cx, "package_event:frame")?;
            let chosen: Vec<&RecordDetection> = frame
                .detections
                .iter()
                .filter(|d| d.class_index == class_index)
                .collect();
            let detections: Vec<Detection> = chosen
                .iter()
                .map(|d| Detection {
                    box_x: f64::from(d.bounds[0]) / 256.0,
                    box_y: f64::from(d.bounds[1]) / 256.0,
                    box_w: f64::from(d.bounds[2].saturating_sub(d.bounds[0])) / 256.0,
                    box_h: f64::from(d.bounds[3].saturating_sub(d.bounds[1])) / 256.0,
                })
                .collect();
            let output = tracker.try_step(&detections, TrackerLimits::default())?;
            for target in output.tracks.iter().filter(|t| t.misses == 0) {
                let track_box = [
                    rounded(target.cx),
                    rounded(target.cy),
                    rounded(target.box_w),
                    rounded(target.box_h),
                ];
                let detection = chosen
                    .iter()
                    .map(|d| (d, iou_ppm(d.bounds, track_box)))
                    .filter(|(_, iou)| *iou > 0)
                    .max_by(|(a, x), (b, y)| {
                        x.cmp(y)
                            .then(
                                f32::from_bits(a.score_bits)
                                    .total_cmp(&f32::from_bits(b.score_bits)),
                            )
                            .then(b.row.cmp(&a.row))
                    })
                    .map(|(d, iou)| (d.row, d.score_bits, d.bounds, iou));
                let entry = tracks.entry(target.id).or_insert_with(|| PackageTrack {
                    identity: ContentDigest::sha256(&[]),
                    track_id: target.id,
                    confirmed: false,
                    observations: Vec::new(),
                });
                entry.confirmed |= target.status == TrackStatus::Confirmed;
                entry.observations.push(PackageObservation {
                    segment: frame.segment,
                    capsule_digest: frame.capsule_digest,
                    track_box,
                    detection,
                });
            }
        }
        let mut tracks: Vec<PackageTrack> = tracks.into_values().collect();
        for track in &mut tracks {
            let mut e = CanonicalEncoder::new();
            e.text(TRACK_DOMAIN);
            e.digest(retained.record_digest());
            e.text(label);
            e.u32(config.confirmation_hits);
            e.u32(config.maximum_missed_frames);
            e.u32(config.minimum_iou_ppm);
            e.u64(track.track_id);
            track.identity = ContentDigest::sha256(&e.finish());
        }
        let bytes = encode_report(&retained, label, class_index, config, &tracks)?;
        if bytes.len() > MAX_PACKAGE_ANALYSIS_BYTES {
            return Err(PackageEventError::Limit);
        }
        Ok(Self {
            retained,
            label: label.to_owned(),
            class_index,
            config,
            tracks,
            digest: ContentDigest::sha256(&bytes),
            bytes,
        })
    }

    /// Verifies exported report bytes by rebuilding them from retained custody.
    pub fn verify(
        deployment: &ReferenceDeployment,
        bytes: &[u8],
        expected: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self> {
        if bytes.len() > MAX_PACKAGE_ANALYSIS_BYTES {
            return Err(PackageEventError::Limit);
        }
        if ContentDigest::sha256(bytes) != expected {
            return Err(PackageEventError::Mismatch);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.bytes()? != REPORT_MAGIC
            || d.u32()? != 1
            || d.text()? != PACKAGE_ANALYSIS_REPORT_DOMAIN
        {
            return Err(PackageEventError::InvalidRequest(
                "not a package analysis report",
            ));
        }
        let _policy = d.digest()?;
        let report_digest = d.digest()?;
        let _record = d.digest()?;
        let label = text(&mut d)?;
        let _class = d.u64()?;
        let config = PackageTrackingConfig {
            confirmation_hits: d.u32()?,
            maximum_missed_frames: d.u32()?,
            minimum_iou_ppm: d.u32()?,
        };
        let report = Self::read(deployment, report_digest, &label, config, cx)?;
        if report.bytes != bytes {
            return Err(PackageEventError::Mismatch);
        }
        Ok(report)
    }

    /// Canonical bytes.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.bytes
    }
    /// SHA-256 of the canonical bytes.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Retained detection the report was rebuilt from.
    #[must_use]
    pub fn retained(&self) -> &RetainedPackageDetection {
        &self.retained
    }
    /// Tracked label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    /// Every track of the label, confirmed or not, in tracker-id order.
    #[must_use]
    pub fn tracks(&self) -> &[PackageTrack] {
        &self.tracks
    }
    /// Index of the tracked label in the package vocabulary.
    #[must_use]
    pub fn class_index(&self) -> u64 {
        self.class_index
    }
    /// Tracking policy.
    #[must_use]
    pub fn config(&self) -> PackageTrackingConfig {
        self.config
    }
}

fn encode_report(
    retained: &RetainedPackageDetection,
    label: &str,
    class_index: u64,
    config: PackageTrackingConfig,
    tracks: &[PackageTrack],
) -> Result<Vec<u8>> {
    let record = retained.record();
    let mut e = CanonicalEncoder::new();
    e.bytes(REPORT_MAGIC);
    e.u32(1);
    e.text(PACKAGE_ANALYSIS_REPORT_DOMAIN);
    e.digest(ContentDigest::sha256(POLICY));
    e.digest(record.report_digest);
    e.digest(retained.record_digest());
    e.text(label);
    e.u64(class_index);
    e.u32(config.confirmation_hits);
    e.u32(config.maximum_missed_frames);
    e.u32(config.minimum_iou_ppm);
    e.digest(retained.root());
    e.u64(record.frames.len() as u64);
    for frame in &record.frames {
        e.u64(frame.segment);
        e.digest(frame.capsule_digest);
        e.u64(
            frame
                .detections
                .iter()
                .filter(|d| d.class_index == class_index)
                .count() as u64,
        );
    }
    e.u64(tracks.len() as u64);
    for track in tracks {
        e.digest(track.identity);
        e.u64(track.track_id);
        e.bool(track.confirmed);
        e.u64(track.observations.len() as u64);
        for o in &track.observations {
            e.u64(o.segment);
            e.digest(o.capsule_digest);
            for value in o.track_box {
                e.i128(i128::from(value));
            }
            match o.detection {
                Some((row, score, bounds, iou)) => {
                    e.u8(1);
                    e.u64(row);
                    e.u32(score);
                    for value in bounds {
                        e.u32(value);
                    }
                    e.u32(iou);
                }
                None => e.u8(0),
            }
        }
    }
    Ok(e.finish_checked()?)
}

/// Publication state of a package event proposal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackageEventStatus {
    /// Prepared; no event authority exists yet.
    Prepared,
    /// This exact revision is already authoritative.
    AlreadyPublished,
    /// Published by this call.
    Published,
}

#[derive(Clone, Debug)]
struct Provenance {
    slot: SlotName,
    manifest: ObjectManifest,
    objects: BTreeMap<ContentDigest, Vec<u8>>,
    event: EventHypothesis,
}

/// Read-only preparation of one exact package event revision.
#[derive(Clone, Debug)]
pub struct PackageEventProposal {
    report: PackageAnalysisReport,
    track: ContentDigest,
    proof: Provenance,
    digest: ContentDigest,
    status: PackageEventStatus,
}

fn insert(objects: &mut BTreeMap<ContentDigest, Vec<u8>>, bytes: Vec<u8>) -> ContentDigest {
    let digest = ContentDigest::sha256(&bytes);
    objects.insert(digest, bytes);
    digest
}

fn provenance(report: &PackageAnalysisReport, track: ContentDigest) -> Result<Provenance> {
    let selected = report
        .tracks
        .iter()
        .find(|t| t.identity == track && t.confirmed)
        .ok_or(PackageEventError::TrackUnavailable)?;
    let record = report.retained.record();
    let frames: BTreeMap<u64, &RecordFrame> =
        record.frames.iter().map(|f| (f.segment, f)).collect();
    let sensor = &record
        .frames
        .first()
        .ok_or(PackageEventError::Limit)?
        .sensor_id;
    let mut objects = BTreeMap::new();
    insert(&mut objects, report.bytes.clone());
    let policy = insert(&mut objects, POLICY.to_vec());
    let sensor_digest = insert(&mut objects, sensor.as_bytes().to_vec());
    let failure_domain = format!("recorded-sensor:{}", hex(sensor_digest));
    let mut children = BTreeSet::from([record.import_root, report.retained.root()]);
    let mut evidence = Vec::with_capacity(selected.observations.len());
    let mut interval: Option<CaptureInterval> = None;
    for o in &selected.observations {
        let frame = frames.get(&o.segment).ok_or(PackageEventError::Mismatch)?;
        if frame.sensor_id != *sensor {
            return Err(PackageEventError::Mismatch);
        }
        let mut e = CanonicalEncoder::new();
        e.text(OBSERVATION_DOMAIN);
        e.digest(report.digest);
        e.digest(track);
        e.digest(record.package_digest);
        e.text(&record.generation);
        e.u64(o.segment);
        e.digest(o.capsule_digest);
        e.digest(frame.inference_identity);
        e.digest(frame.output_digest);
        e.digest(frame.detection_report_digest);
        for value in o.track_box {
            e.i128(i128::from(value));
        }
        match o.detection {
            Some((row, score, bounds, iou)) => {
                e.u8(1);
                e.text(&report.label);
                e.u64(row);
                e.u32(score);
                for value in bounds {
                    e.u32(value);
                }
                e.u32(iou);
            }
            None => e.u8(0),
        }
        e.text("uncalibrated");
        let digest = insert(&mut objects, e.finish());
        children.insert(o.capsule_digest);
        interval = Some(match interval {
            Some(old) => CaptureInterval::new(
                old.earliest.min(frame.capture.earliest),
                old.latest.max(frame.capture.latest),
            )?,
            None => frame.capture,
        });
        let supports = o.detection.is_some();
        evidence.push(EventEvidence {
            digest,
            class: EvidenceClass::Derived,
            failure_domain: failure_domain.clone(),
            supports,
            relation: if supports {
                EvidenceEdgeRelation::Supports
            } else {
                EvidenceEdgeRelation::DerivedFrom
            },
            capsule_digest: Some(o.capsule_digest),
            identity_digest: Some(sensor_digest),
        });
    }
    let interval = interval.ok_or(PackageEventError::TrackUnavailable)?;
    let mut e = CanonicalEncoder::new();
    e.bytes(b"FSSPEVT1");
    e.u32(1);
    e.text(PROVENANCE_DOMAIN);
    e.digest(policy);
    e.digest(track);
    e.digest(report.digest);
    let metadata = insert(&mut objects, e.finish());
    children.extend(objects.keys().copied());
    children.remove(&metadata);
    let mut e = CanonicalEncoder::new();
    e.text(PROVENANCE_DOMAIN);
    e.digest(track);
    e.digest(report.digest);
    let slot = SlotName::parse(&format!("pe-{}", hex(ContentDigest::sha256(&e.finish()))))
        .map_err(|_| PackageEventError::Mismatch)?;
    let manifest = ObjectManifest::new(slot.as_str(), children, Some(metadata))?;
    evidence.sort_by_key(|e| e.digest);
    let event = EventHypothesis {
        schema: EventHypothesis::SCHEMA.to_owned(),
        event_id: EventId::parse(format!("event:package:{}", hex(track)))?,
        revision: 1,
        supersedes: None,
        state: EventState::Indeterminate,
        kind: EventKind::Unclassified,
        interval,
        uncertainty_reason: Some(UNCERTAINTY.to_owned()),
        zone_ids: Vec::new(),
        track_ids: vec![hex(track)],
        probability: ProbabilityInterval::new(0.0, 1.0)?,
        evidence,
        model_receipts: Vec::new(),
        decision_path: DecisionPath {
            policy_generation: policy,
            fingerprint: manifest.root(),
            abstained: true,
            abstention_reason: Some(ABSTENTION.to_owned()),
        },
    };
    event.validate()?;
    Ok(Provenance {
        slot,
        manifest,
        objects,
        event,
    })
}

fn current_status(
    deployment: &ReferenceDeployment,
    event: &EventHypothesis,
) -> Result<PackageEventStatus> {
    let object = ObjectId::parse(format!("object:event:{}", event.event_id.as_str()))?;
    let Some(current) = deployment.ledger().current().objects.get(&object) else {
        return Ok(PackageEventStatus::Prepared);
    };
    let revision = event.revision_digest();
    let exact = deployment.ledger().batches().iter().any(|batch| {
        batch.deltas.iter().any(|delta| {
            delta.object_id == object
                && delta.family == "event_revision"
                && delta.new_generation == current.generation
                && delta.payload_digest == current.payload_digest
                && delta.witness_digest == Some(revision)
        })
    });
    if exact {
        Ok(PackageEventStatus::AlreadyPublished)
    } else {
        Err(PackageEventError::Conflict)
    }
}

/// Completed publication.
#[derive(Clone, Debug)]
pub struct PackageEventReceipt {
    /// Published (or already published) event.
    pub event: EventHypothesis,
    /// Canonical event revision root.
    pub event_root: ContentDigest,
    /// Anchor of the event authority commit.
    pub authority_anchor: LedgerAnchor,
    /// Provenance root retained before the event.
    pub provenance_root: ContentDigest,
    /// Analysis report digest.
    pub report_digest: ContentDigest,
    /// Track identity.
    pub track: ContentDigest,
}

impl PackageEventProposal {
    /// Verifies the report from retained custody and prepares the event of one confirmed
    /// track. Writes nothing.
    pub fn prepare(
        deployment: &ReferenceDeployment,
        report_bytes: &[u8],
        report_digest: ContentDigest,
        track: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<Self> {
        checkpoint(cx, "package_event:prepare")?;
        let report = PackageAnalysisReport::verify(deployment, report_bytes, report_digest, cx)?;
        let proof = provenance(&report, track)?;
        let status = current_status(deployment, &proof.event)?;
        let mut e = CanonicalEncoder::new();
        e.text(PROPOSAL_DOMAIN);
        e.digest(proof.event.revision_digest());
        e.digest(proof.manifest.root());
        let digest = ContentDigest::sha256(&e.finish_checked()?);
        Ok(Self {
            report,
            track,
            proof,
            digest,
            status,
        })
    }
    /// Exact approval identity (event revision digest plus provenance root).
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Proposed event.
    #[must_use]
    pub fn event(&self) -> &EventHypothesis {
        &self.proof.event
    }
    /// Provenance root.
    #[must_use]
    pub fn provenance_root(&self) -> ContentDigest {
        self.proof.manifest.root()
    }
    /// Publication state when prepared.
    #[must_use]
    pub fn status(&self) -> PackageEventStatus {
        self.status
    }

    /// Revalidates the exact approval, retains provenance root-last, then publishes through
    /// the guarded event publisher. Exact retries keep the same revision and anchor.
    pub fn publish(
        &self,
        deployment: &mut ReferenceDeployment,
        expected: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<PackageEventReceipt> {
        checkpoint(cx, "package_event:revalidate")?;
        if expected != self.digest {
            return Err(PackageEventError::StaleProposal);
        }
        let fresh = Self::prepare(
            deployment,
            self.report.encoded(),
            self.report.digest(),
            self.track,
            cx,
        )?;
        if fresh.digest != expected {
            return Err(PackageEventError::StaleProposal);
        }
        let proof = &fresh.proof;
        if fresh.status == PackageEventStatus::AlreadyPublished {
            // Never republished: report the committed revision without writing anything.
            let object =
                ObjectId::parse(format!("object:event:{}", proof.event.event_id.as_str()))?;
            let revision = proof.event.revision_digest();
            let (anchor, root) = deployment
                .ledger()
                .batches()
                .iter()
                .rev()
                .find_map(|batch| {
                    batch
                        .deltas
                        .iter()
                        .find(|d| {
                            d.object_id == object
                                && d.family == "event_revision"
                                && d.witness_digest == Some(revision)
                        })
                        .map(|d| (batch.new_anchor.clone(), d.payload_digest))
                })
                .ok_or(PackageEventError::Mismatch)?;
            return Ok(PackageEventReceipt {
                event: proof.event.clone(),
                event_root: root,
                authority_anchor: anchor,
                provenance_root: proof.manifest.root(),
                report_digest: fresh.report.digest(),
                track: fresh.track,
            });
        }
        let existing_root = deployment.publisher().root(&proof.slot).map(|r| r.root);
        if existing_root.is_some_and(|root| root != proof.manifest.root()) {
            return Err(PackageEventError::Mismatch);
        }
        for bytes in proof.objects.values() {
            checkpoint(cx, "package_event:stage")?;
            let digest = deployment.publisher_mut().stage_object(bytes)?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        for digest in proof.manifest.children() {
            checkpoint(cx, "package_event:closure")?;
            deployment.publisher_mut().verify_object(*digest)?;
        }
        if existing_root.is_none() {
            deployment
                .publisher_mut()
                .stage_manifest(&proof.slot, &proof.manifest)?;
        }
        deployment.publish_and_commit(&proof.slot, &proof.manifest, proof.event.interval, cx)?;
        checkpoint(cx, STAGE_PACKAGE_EVENT_COMMIT)?;
        let receipt = deployment.publish_event(
            &ReferencePolicyDecision {
                event: proof.event.clone(),
                action: ReferencePolicyAction::Hold,
            },
            cx,
        )?;
        cx.checkpoint_post_commit("package_event:published");
        Ok(PackageEventReceipt {
            event: proof.event.clone(),
            event_root: receipt.event_root,
            authority_anchor: receipt.authority_anchor,
            provenance_root: proof.manifest.root(),
            report_digest: fresh.report.digest(),
            track: fresh.track,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> PackageDetectionRecord {
        let digest = |tag: &[u8]| ContentDigest::sha256(tag);
        PackageDetectionRecord {
            report_digest: digest(b"report"),
            package_digest: digest(b"package"),
            manifest_digest: digest(b"manifest"),
            model_id: "MOD-YOLOXNANO-001".into(),
            generation: "g1".into(),
            model_digest: digest(b"model"),
            graph_digest: digest(b"graph"),
            contract_digest: digest(b"contract"),
            import_identity: digest(b"import"),
            import_root: digest(b"root"),
            media_format: "mjpeg".into(),
            first_segment: 3,
            segment_count: 1,
            minimum_score_ppm: 300_000,
            labels: vec!["person".into(), "car".into()],
            frames: vec![RecordFrame {
                segment: 3,
                capsule_digest: digest(b"capsule"),
                sensor_id: "sensor:a".into(),
                capture: CaptureInterval {
                    earliest: TimestampNs(10),
                    latest: TimestampNs(20),
                },
                dimensions: [64, 48],
                color: "jpeg_rgb".into(),
                inference_identity: digest(b"inference"),
                output_digest: digest(b"output"),
                detection_report_digest: digest(b"head"),
                detections: vec![RecordDetection {
                    row: 7,
                    class_index: 0,
                    score_bits: 0.75_f32.to_bits(),
                    bounds: [0, 0, 256, 512],
                    clipped: false,
                }],
            }],
        }
    }

    #[test]
    fn record_round_trips_and_every_truncation_or_trailing_byte_is_refused() -> Result<()> {
        let record = record();
        let bytes = record.encode()?;
        assert_eq!(PackageDetectionRecord::decode(&bytes)?, record);
        for end in 0..bytes.len() {
            assert!(PackageDetectionRecord::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PackageDetectionRecord::decode(&trailing).is_err());
        Ok(())
    }

    #[test]
    fn tracking_policy_bounds_and_explicit_overrides_are_checked() {
        assert!(
            PackageTrackingConfig {
                confirmation_hits: 0,
                maximum_missed_frames: 1,
                minimum_iou_ppm: 100_000,
            }
            .tracker()
            .is_err()
        );
        assert!(
            PackageTrackingConfig {
                confirmation_hits: 1,
                maximum_missed_frames: 1,
                minimum_iou_ppm: 1_000_001,
            }
            .tracker()
            .is_err()
        );
        assert!(!PackageAnalysisReport::is_package_report(b"FSSARPT1"));
    }
}
