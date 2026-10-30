#![forbid(unsafe_code)]
//! Exact-approval, event-linked original footage for an independent local export package.
//!
//! This is a separate disclosure profile from `evidence_export`'s redacted metadata. It admits
//! complete MJPEG sources and native, video-only RTSP MP4 imports. The selected source must belong
//! to a current, source-verified long-watch, long-dwell, long-corroboration or retained detector-
//! package event. Whole-source
//! context is explicit: no frame-accurate trim, redaction, inference, or multi-camera concatenation
//! occurs. A masked sensor has no override path.
//!
//! Preparation and approval do not write anything or claim delivery. The filesystem adapter must
//! write and read back the two children, retain the deployment's exclusive publication lease, call
//! [`revalidate_original_media_export`], and publish the completion/root marker last. Consequently
//! an unsuccessful output never leaves a misleading export-complete authority row or an additional
//! retained media replica. The independently supplied package root verifies only the selected bytes
//! and custody record; offline verification does not rerun packet custody or certify scene truth.

use std::fmt;

use fss_core::region::ContextAuthority;
use fss_core::{
    CanonicalEncode, CaptureInterval, ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor,
    ObjectId, PrincipalId, SensorId,
};
use fss_object::{ObjectError, ObjectManifest, SpoolError};

use crate::event_review::{
    ReviewError,
    lineage::{VerifiedReviewLink, inspect_review_lineage},
};
use crate::evidence_export::{
    CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE, EventExportRecord, EventExportRequest, ExportError,
    preview_export,
};
use crate::ingest::long_event_replay::{
    LongEventReplayError, LongEventReplayLimits, LongEventReplayRecipe, inspect_long_event,
    inspect_review_origin,
};
use crate::ingest::package_event::{PackageEvent, PackageEventError};
use crate::ingest::privacy_mask::{PrivacyMaskError, binding_digest, refuse_unmasked_source};
use crate::ingest::recorded_decode::{RecordedDecodeError, retained_source_capsule};
use crate::ingest::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReplayCx};

mod wire;

/// Existing positive private-media read grant, required in addition to export prepare/commit.
/// Metadata export grants alone never permit original, unredacted video disclosure.
pub const CAP_EXPORT_ORIGINAL_MEDIA: &str = "CAP-READ-MEDIA-001";
/// Fixed whole-source disclosure profile. The existing metadata-only profile is unchanged.
pub const ORIGINAL_MEDIA_EXPORT_PROFILE: &str = "event-original-media-whole-source-v1";
/// Complete verified operator-review lineage plus the original native source computation.
pub const REVIEWED_ORIGINAL_MEDIA_EXPORT_PROFILE: &str =
    "event-reviewed-original-media-whole-source-v2";
/// Source-verified trained-package candidate; its classification remains uncalibrated.
pub const PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE: &str =
    "event-package-original-media-whole-source-v3";
/// Complete operator-review lineage over an unchanged native trained-package candidate.
pub const REVIEWED_PACKAGE_ORIGINAL_MEDIA_EXPORT_PROFILE: &str =
    "event-reviewed-package-original-media-whole-source-v4";
/// Largest returned original source allocation; no implicit stream or unbounded concatenation.
pub const MAX_ORIGINAL_MEDIA_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum source capsules whose camera, interval and privacy scope are checked before disclosure.
pub const MAX_ORIGINAL_MEDIA_SEGMENTS: usize = 16_384;
/// Maximum complete canonical custody record.
pub const MAX_ORIGINAL_MEDIA_RECORD_BYTES: usize = 128 * 1024;
/// Canonical custody record domain.
pub const ORIGINAL_MEDIA_EXPORT_DOMAIN: &str = "fss.original_media_export.v1";
/// Explicit version for reviewed-event custody; original revision-one records remain v1.
pub const REVIEWED_ORIGINAL_MEDIA_EXPORT_DOMAIN: &str = "fss.original_media_export.v2";
/// Explicit version for native detector-package event source custody.
pub const PACKAGE_ORIGINAL_MEDIA_EXPORT_DOMAIN: &str = "fss.original_media_export.v3";
/// Explicit version for reviewed trained-package source custody and operator assertion pins.
pub const REVIEWED_PACKAGE_ORIGINAL_MEDIA_EXPORT_DOMAIN: &str = "fss.original_media_export.v4";
const POLICY: &[u8] = b"fss.original_media_export.policy.v1:current-original-long-event:exact-import-root:whole-source-explicit:video-only-native-rtsp-or-complete-mjpeg:no-mask-override:recipient-purpose-expiry-attestation:destination-bound:separate-original-media-capability:revalidate-before-root-last-output:no-delivery-claim-before-readback";
const REVIEWED_POLICY: &[u8] = b"fss.original_media_export.policy.v2:current-reviewed-long-event:complete-exact-operator-review-derivation:native-origin-source-closure:no-new-sensor-support:review-rationale-and-principal-redacted:exact-import-root:whole-source-explicit:video-only-native-rtsp-or-complete-mjpeg:no-mask-override:recipient-purpose-expiry-attestation:destination-bound:separate-original-media-capability:revalidate-before-root-last-output:no-delivery-claim-before-readback";
const PACKAGE_POLICY: &[u8] = b"fss.original_media_export.policy.v3:current-native-package-event:exact-retained-detection-and-tracking-proof:source-closed-no-inference-reexecution:uncalibrated-unclassified-indeterminate-no-alert-authority:exact-import-root:whole-source-explicit:video-only-native-rtsp-or-complete-mjpeg:no-mask-override:recipient-purpose-expiry-attestation:destination-bound:separate-original-media-capability:revalidate-before-root-last-output:no-delivery-claim-before-readback";
const REVIEWED_PACKAGE_POLICY: &[u8] = b"fss.original_media_export.policy.v4:current-reviewed-package-event:complete-exact-operator-review-derivation:sealed-native-origin-exact-retained-detection-and-tracking-proof:source-closed-no-inference-reexecution:uncalibrated-unclassified-indeterminate-native-origin-no-alert-authority:no-new-sensor-support:review-rationale-and-principal-redacted:exact-import-root:whole-source-explicit:video-only-native-rtsp-or-complete-mjpeg:no-mask-override:recipient-purpose-expiry-attestation:destination-bound:separate-original-media-capability:revalidate-before-root-last-output:no-delivery-claim-before-readback";
type Result<T> = std::result::Result<T, OriginalMediaExportError>;

/// Exact source and recipient disclosure reviewed by the owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalMediaExportRequest {
    /// Current event revision, recipient, purpose, and exclusive expiry.
    pub event: EventExportRequest,
    /// One source actually belonging to that event's retained computation.
    pub import_identity: ContentDigest,
    /// Independently selected completed import root.
    pub expected_import_root: ContentDigest,
    /// Required acknowledgement that context before/after the event will also be disclosed.
    pub whole_source_authorized: bool,
    /// Digest of the output adapter's canonical, create-only destination binding.
    pub destination_binding: ContentDigest,
    /// Explicit source-length ceiling, at most [`MAX_ORIGINAL_MEDIA_BYTES`].
    pub max_source_bytes: u64,
    /// Operator-attested current-time interval; never substituted by an ambient host clock.
    pub attested_now: CaptureInterval,
}
impl OriginalMediaExportRequest {
    /// Reject malformed bounds, missing whole-source permission, and expired/uncertain expiry.
    pub fn validate(&self) -> Result<()> {
        self.event.validate()?;
        if !self.whole_source_authorized
            || !(1..=MAX_ORIGINAL_MEDIA_BYTES).contains(&self.max_source_bytes)
            || ![
                self.import_identity,
                self.expected_import_root,
                self.destination_binding,
            ]
            .into_iter()
            .all(valid_digest)
            || self.attested_now.earliest > self.attested_now.latest
        {
            return Err(OriginalMediaExportError::InvalidRequest);
        }
        if self.attested_now.latest >= self.event.expires_at {
            return Err(OriginalMediaExportError::Expired);
        }
        Ok(())
    }
    fn read_limits(&self) -> RetainedReadLimits {
        RetainedReadLimits {
            max_source_bytes: self.max_source_bytes,
            max_chunk_bytes: MAX_ORIGINAL_MEDIA_BYTES,
            max_segment_bytes: MAX_ORIGINAL_MEDIA_BYTES,
        }
    }
}

/// Verified custody and explicit disclosure semantics of the two-child portable package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalMediaExportRecord {
    request: OriginalMediaExportRequest,
    event_summary: EventExportRecord,
    basis: LedgerAnchor,
    authority_binding: ContentDigest,
    event_provenance_root: ContentDigest,
    analysis_roots: Vec<ContentDigest>,
    event_profile: String,
    event_source_count: u32,
    source_adapter: String,
    source_manifest: ContentDigest,
    source_format: MediaFormat,
    source_sensor: SensorId,
    source_digest: ContentDigest,
    source_bytes: u64,
    source_segments: u64,
    source_interval: CaptureInterval,
    source_capture_label: String,
    review_lineage: Option<ReviewedMediaLineage>,
}

/// Immutable redacted proof pins. The complete plaintext review chain is checked only in the
/// deployment; an offline package binds these pins without making them independent sensor truth.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ReviewedMediaLineage {
    original_revision: ContentDigest,
    original_root: ContentDigest,
    original_anchor: LedgerAnchor,
    links: Vec<VerifiedReviewLink>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MediaFormat {
    Mjpeg,
    Mp4Avc,
    Mp4Hevc,
}
impl MediaFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Mjpeg => "mjpeg",
            Self::Mp4Avc => "mp4avc",
            Self::Mp4Hevc => "mp4hevc",
        }
    }
    fn filename(self) -> &'static str {
        match self {
            Self::Mjpeg => "source.mjpeg",
            Self::Mp4Avc | Self::Mp4Hevc => "source.mp4",
        }
    }
}

/// Complete read-only preview. Bytes are immutable and private to the approved composition.
#[derive(Debug)]
pub struct OriginalMediaExportPreview {
    record: OriginalMediaExportRecord,
    record_bytes: Vec<u8>,
    manifest_bytes: Vec<u8>,
    root: ContentDigest,
    media_bytes: Vec<u8>,
}
impl OriginalMediaExportPreview {
    /// Exact approval over the profile, record, two-child root and destination binding.
    pub fn approval(&self) -> ContentDigest {
        let mut e = fss_core::CanonicalEncoder::new();
        e.text("fss.original_media_export_approval.v1");
        e.digest(ContentDigest::sha256(self.record.policy()));
        e.digest(self.record.digest());
        e.digest(self.root);
        ContentDigest::sha256(&e.finish())
    }
    /// Independently pin this root when verifying a delivered package.
    pub const fn root(&self) -> ContentDigest {
        self.root
    }
    /// Versioned disclosure profile, distinct for original and reviewed current events.
    pub fn profile(&self) -> &'static str {
        self.record.profile()
    }
    /// Human/machine projection; canonical bytes define identity.
    pub fn record_json(&self) -> String {
        self.record.to_json()
    }
    /// Expected hash of the exact playable source bytes.
    pub fn media_digest(&self) -> ContentDigest {
        self.record.source_digest
    }
    /// Entire original source, with no removed or rewritten bytes.
    pub fn media_bytes(&self) -> &[u8] {
        &self.media_bytes
    }
    /// Fixed filename determined by the admitted video-only format.
    pub fn media_filename(&self) -> &'static str {
        self.record.media_filename()
    }
    /// Complete canonical custody record; one manifest child.
    pub fn record_bytes(&self) -> &[u8] {
        &self.record_bytes
    }
    /// Complete canonical manifest; publish only after verified children and fresh revalidation.
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }
    /// Exact owner request.
    pub fn request(&self) -> &OriginalMediaExportRequest {
        &self.record.request
    }
    /// Exact deployment head included in approval.
    pub fn basis(&self) -> &LedgerAnchor {
        &self.record.basis
    }
    /// Typed custody record.
    pub fn record(&self) -> &OriginalMediaExportRecord {
        &self.record
    }
}

/// An explicitly approved package, not a delivery or publication receipt.
#[derive(Debug)]
pub struct PreparedOriginalMediaExport {
    preview: OriginalMediaExportPreview,
}
impl PreparedOriginalMediaExport {
    /// Authorized immutable package to stage at the exact destination.
    pub fn preview(&self) -> &OriginalMediaExportPreview {
        &self.preview
    }
}

/// Typed refusal. No refusal returns partial source bytes or a successful delivery record.
#[derive(Debug)]
pub enum OriginalMediaExportError {
    /// Missing acknowledgement, malformed digest, time interval or resource ceiling.
    InvalidRequest,
    /// Missing original-video capability, mismatched scope, or an exhausted authority deadline.
    Unauthorized,
    /// Attested current time reaches or crosses the exclusive expiry.
    Expired,
    /// Current approval no longer matches the exact event/source/destination/scope/time request.
    StaleApproval,
    /// The exact deployment head changed; a fresh preview and approval are required.
    AuthorityChanged,
    /// The selected import is not a source of this exact supported event.
    SourceNotInEvent,
    /// Unsupported event or media/channel/omission profile; no fallback disclosure occurs.
    UnsupportedProfile,
    /// Canonical record, source bytes, import root or manifest closure differ.
    CustodyMismatch,
    /// One explicit allocation, source or metadata limit was exhausted.
    Limit,
    /// Cooperative owner cancellation.
    Cancelled,
    /// Existing redacted event authority/metadata owner refused.
    Event(ExportError),
    /// Existing source-closed event inspector refused.
    Inspection(Box<LongEventReplayError>),
    /// Existing trained-package event owner refused its exact current source/provenance graph.
    Package(Box<PackageEventError>),
    /// Complete operator-review lineage or exact immutable derivation could not be verified.
    Review(Box<ReviewError>),
    /// Existing retained-source owner refused, including committed deletion.
    Source(Box<FileIngestError>),
    /// Existing source-capsule custody owner refused.
    Capsule(Box<RecordedDecodeError>),
    /// Current sensor masking prohibits unredacted source disclosure.
    Privacy(PrivacyMaskError),
    /// Canonical contract decoding failed.
    Contract(ContractError),
    /// Native manifest validation failed.
    Object(ObjectError),
    /// Bounded content-addressed storage read failed.
    Spool(SpoolError),
}
impl OriginalMediaExportError {
    /// Stable refusal identity, preserving lower owners' deletion and privacy diagnoses.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "ERR-EXPORT-REQUEST-001",
            Self::Unauthorized => "ERR-AUTH-DENIED-001",
            Self::Expired => "ERR-EXPORT-EXPIRED-001",
            Self::StaleApproval | Self::AuthorityChanged => "ERR-EXPORT-APPROVAL-STALE-001",
            Self::SourceNotInEvent | Self::CustodyMismatch => "ERR-EXPORT-CUSTODY-001",
            Self::UnsupportedProfile => "ERR-EXPORT-MEDIA-PROFILE-001",
            Self::Limit => "ERR-EXPORT-BOUND-001",
            Self::Cancelled => "ERR-EXPORT-CANCELLED-001",
            Self::Event(e) => e.stable_id(),
            Self::Inspection(e) => e.stable_id(),
            Self::Package(e) => e.stable_id(),
            Self::Review(e) => e.stable_id(),
            Self::Source(e) => e.stable_id().unwrap_or("ERR-EXPORT-CUSTODY-001"),
            Self::Capsule(e) => e.stable_id(),
            Self::Privacy(e) => e.stable_id(),
            Self::Contract(_) | Self::Object(_) | Self::Spool(_) => "ERR-EXPORT-CUSTODY-001",
        }
    }
}
impl fmt::Display for OriginalMediaExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.stable_id())?;
        match self {
            Self::InvalidRequest => f.write_str("invalid bounded whole-source export request"),
            Self::Unauthorized => f.write_str("original-footage disclosure authority denied"),
            Self::Expired => {
                f.write_str("attested current time is not wholly before export expiry")
            }
            Self::StaleApproval => {
                f.write_str("approval differs from this exact original-media package")
            }
            Self::AuthorityChanged => {
                f.write_str("deployment head changed; preview and approve again")
            }
            Self::SourceNotInEvent => {
                f.write_str("selected retained import does not belong to this event")
            }
            Self::UnsupportedProfile => f.write_str(
                "unsupported original event, video-only source or complete-source profile",
            ),
            Self::CustodyMismatch => f.write_str("original-media package custody mismatch"),
            Self::Limit => f.write_str("original-media export bound exceeded"),
            Self::Cancelled => f.write_str("original-media export cancelled"),
            Self::Event(e) => write!(f, "{e}"),
            Self::Inspection(e) => write!(f, "{e}"),
            Self::Package(e) => write!(f, "{e}"),
            Self::Review(e) => write!(f, "{e}"),
            Self::Source(e) => write!(f, "{e}"),
            Self::Capsule(e) => write!(f, "{e}"),
            Self::Privacy(e) => write!(f, "{e}"),
            Self::Contract(e) => write!(f, "{e}"),
            Self::Object(e) => write!(f, "{e}"),
            Self::Spool(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for OriginalMediaExportError {}
macro_rules! from_error {
    ($ty:ty, $variant:ident) => {
        impl From<$ty> for OriginalMediaExportError {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        }
    };
    ($ty:ty, $variant:ident, boxed) => {
        impl From<$ty> for OriginalMediaExportError {
            fn from(value: $ty) -> Self {
                Self::$variant(Box::new(value))
            }
        }
    };
}
from_error!(ExportError, Event);
from_error!(LongEventReplayError, Inspection, boxed);
from_error!(PackageEventError, Package, boxed);
from_error!(ReviewError, Review, boxed);
from_error!(FileIngestError, Source, boxed);
from_error!(RecordedDecodeError, Capsule, boxed);
from_error!(PrivacyMaskError, Privacy);
from_error!(ContractError, Contract);
from_error!(ObjectError, Object);
from_error!(SpoolError, Spool);

fn valid_digest(value: ContentDigest) -> bool {
    value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32]
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| OriginalMediaExportError::Cancelled)
}
fn authorize(
    deployment: &ReferenceDeployment,
    request: &OriginalMediaExportRequest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    commit: bool,
) -> Result<()> {
    request.validate()?;
    authority.validate()?;
    PrincipalId::parse(&authority.principal)?;
    checkpoint(cx, "original_media_export:authority")?;
    if !authority.has_capability(CAP_EXPORT_ORIGINAL_MEDIA)
        || !authority.has_capability(CAP_EXPORT_PREPARE)
        || (commit && !authority.has_capability(CAP_EXPORT_COMMIT))
        || authority.cancellation_reason.is_some()
        // A deadline is exclusive and must remain after the entire attested time interval.
        // ReplayCx checkpoints enforce cancellation, but do not supply an ambient clock.
        || authority
            .deadline
            .is_some_and(|deadline| deadline <= request.attested_now.latest)
        || authority.principal != cx.io_authority().principal()
        || cx.root_dir() != deployment.root()
        || authority.anchor_universe != ContentDigest::sha256(deployment.site_lineage().as_bytes())
        || authority.budgets.bytes < request.max_source_bytes
    {
        return Err(OriginalMediaExportError::Unauthorized);
    }
    Ok(())
}
fn authority_binding(authority: &ContextAuthority) -> ContentDigest {
    let mut e = fss_core::CanonicalEncoder::new();
    e.text("fss.original_media_export_authority.v1");
    e.text(&authority.principal);
    e.text(&authority.privacy_scope);
    e.text(&authority.retention_scope);
    e.digest(authority.anchor_universe);
    e.u64(authority.generation);
    ContentDigest::sha256(&e.finish())
}
fn is_native_rtsp(adapter: &str) -> bool {
    matches!(
        adapter,
        crate::ingest::rtsp_import::ADAPTER
            | crate::ingest::rtsp_import::catalog::ADAPTER
            | crate::ingest::rtsp_import::pages::ADAPTER
    )
}

fn prepare_record(
    deployment: &ReferenceDeployment,
    request: &OriginalMediaExportRequest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<(OriginalMediaExportRecord, RetainedFileImport)> {
    authorize(deployment, request, authority, cx, false)?;
    let basis = deployment.current_anchor().clone();
    // The existing owner verifies current event authority, exact source capsules, source roots,
    // native analysis provenance and current privacy. A caller-selected import alone proves none
    // of those relationships. Inspection never runs a model or changes event interpretation.
    let object = ObjectId::parse(format!("object:event:{}", request.event.event_id.as_str()))?;
    let current = deployment
        .ledger()
        .current()
        .objects
        .get(&object)
        .ok_or(OriginalMediaExportError::CustodyMismatch)?;
    let (event_provenance_root, analysis_roots, event_profile, event_source_count, review_lineage) =
        if request
            .event
            .event_id
            .as_str()
            .starts_with("event:package:")
        {
            // The namespace selects an owner, never establishes custody. That owner verifies the
            // complete authoritative revision chain, rebuilds the exact tracking report from its
            // retained detections and checks every source capsule and provenance child. It does
            // not rerun inference or accept an operator-reviewed successor as a native candidate.
            // A reviewed export separately proves the entire operator chain before recovering
            // only its sealed native origin through the same package provenance owner.
            let (package, review_lineage) = if current.generation == 1 {
                let package = PackageEvent::open(deployment, &request.event.event_id, cx)?;
                if package.event().revision_digest() != request.event.expected_revision {
                    return Err(ExportError::StaleRevision.into());
                }
                (package, None)
            } else {
                let lineage = inspect_review_lineage(deployment, &request.event.event_id, cx)?;
                if lineage.current().revision_digest() != request.event.expected_revision {
                    return Err(ExportError::StaleRevision.into());
                }
                let package = PackageEvent::open_review_origin(deployment, &lineage, cx)?;
                let redacted = ReviewedMediaLineage {
                    original_revision: lineage.original().revision_digest(),
                    original_root: lineage.original_root(),
                    original_anchor: lineage.original_anchor().clone(),
                    links: lineage.links().to_vec(),
                };
                (package, Some(redacted))
            };
            let detection = package.report().retained();
            if detection.record().import_identity != request.import_identity {
                return Err(OriginalMediaExportError::SourceNotInEvent);
            }
            if detection.record().import_root != request.expected_import_root {
                return Err(OriginalMediaExportError::CustodyMismatch);
            }
            (
                package.event().decision_path.fingerprint,
                vec![detection.root()],
                "package_track".to_owned(),
                1,
                review_lineage,
            )
        } else {
            let (inspection, review_lineage) = if current.generation == 1 {
                let inspection = inspect_long_event(
                    deployment,
                    &request.event.event_id,
                    &LongEventReplayLimits::default(),
                    cx,
                )?;
                if inspection.pins().event_revision != request.event.expected_revision {
                    return Err(ExportError::StaleRevision.into());
                }
                (inspection, None)
            } else {
                // The sealed review owner verifies every link before the original native recipe
                // can be inspected. An operator assertion is not recomputed sensor evidence.
                let lineage = inspect_review_lineage(deployment, &request.event.event_id, cx)?;
                if lineage.current().revision_digest() != request.event.expected_revision {
                    return Err(ExportError::StaleRevision.into());
                }
                let inspection = inspect_review_origin(
                    deployment,
                    &lineage,
                    &LongEventReplayLimits::default(),
                    cx,
                )?;
                let redacted = ReviewedMediaLineage {
                    original_revision: lineage.original().revision_digest(),
                    original_root: lineage.original_root(),
                    original_anchor: lineage.original_anchor().clone(),
                    links: lineage.links().to_vec(),
                };
                (inspection, Some(redacted))
            };
            let (belongs, event_source_count) = match inspection.recipe() {
                LongEventReplayRecipe::Watch(recipe) => {
                    (recipe.plan().import_identity == request.import_identity, 1)
                }
                LongEventReplayRecipe::Dwell(recipe) => {
                    (recipe.plan().import_identity == request.import_identity, 1)
                }
                LongEventReplayRecipe::Corroboration(recipe) => (
                    recipe
                        .plan()
                        .cameras
                        .iter()
                        .any(|camera| camera.import_identity == request.import_identity),
                    2,
                ),
            };
            if !belongs {
                return Err(OriginalMediaExportError::SourceNotInEvent);
            }
            if inspection.basis() != &basis {
                return Err(OriginalMediaExportError::AuthorityChanged);
            }
            (
                inspection.pins().provenance_root,
                inspection.analysis_roots().to_vec(),
                inspection.profile().to_owned(),
                event_source_count,
                review_lineage,
            )
        };
    let retained = RetainedFileImport::open(
        deployment,
        request.import_identity,
        request.read_limits(),
        cx,
    )?;
    if retained.import_root() != request.expected_import_root {
        return Err(OriginalMediaExportError::CustodyMismatch);
    }
    let manifest = retained.manifest();
    if manifest.segment_spans.is_empty()
        || manifest.segment_spans.len() > MAX_ORIGINAL_MEDIA_SEGMENTS
    {
        return Err(OriginalMediaExportError::Limit);
    }
    // General file MP4 imports can retain audio/other-track bytes as container structure. Native
    // RTSP owners have a video-only writer and independently verify original packet custody.
    // Do not silently broaden this profile to generic MP4/MKV merely because perception found
    // one video track. Omitted/truncated MJPEG tails likewise are not video-only attestations.
    let source_format = match manifest.format.as_str() {
        "mjpeg" if manifest.omission_spans.is_empty() => MediaFormat::Mjpeg,
        "mp4avc" if is_native_rtsp(&manifest.adapter_id) => MediaFormat::Mp4Avc,
        "mp4hevc" if is_native_rtsp(&manifest.adapter_id) => MediaFormat::Mp4Hevc,
        _ => return Err(OriginalMediaExportError::UnsupportedProfile),
    };
    if manifest
        .omission_spans
        .iter()
        .any(|span| !span.is_container_structure())
    {
        return Err(OriginalMediaExportError::UnsupportedProfile);
    }
    let mut sensor = None;
    let mut interval: Option<CaptureInterval> = None;
    for index in 0..manifest.segment_spans.len() {
        checkpoint(cx, "original_media_export:capsule")?;
        let capsule = retained_source_capsule(deployment, &retained, index)?;
        if let Some(expected) = &sensor {
            if expected != &capsule.sensor_id {
                return Err(OriginalMediaExportError::CustodyMismatch);
            }
        } else {
            // Privacy is checked before reading source chunks, and covers the whole source,
            // including frames outside the analyzed event interval.
            refuse_unmasked_source(deployment, &capsule.sensor_id)?;
            sensor = Some(capsule.sensor_id.clone());
        }
        interval = Some(match interval {
            Some(prior) => CaptureInterval {
                earliest: prior.earliest.min(capsule.capture.earliest),
                latest: prior.latest.max(capsule.capture.latest),
            },
            None => capsule.capture,
        });
    }
    let event_summary = preview_export(deployment, &request.event, authority, cx)?;
    let record = OriginalMediaExportRecord {
        request: request.clone(),
        event_summary: event_summary.record().clone(),
        basis: basis.clone(),
        authority_binding: authority_binding(authority),
        event_provenance_root,
        analysis_roots,
        event_profile,
        event_source_count,
        source_adapter: manifest.adapter_id.clone(),
        source_manifest: retained.manifest_digest(),
        source_format,
        source_sensor: sensor.ok_or(OriginalMediaExportError::CustodyMismatch)?,
        source_digest: manifest.input_sha256,
        source_bytes: manifest.input_bytes,
        source_segments: manifest.segment_spans.len() as u64,
        source_interval: interval.ok_or(OriginalMediaExportError::CustodyMismatch)?,
        source_capture_label: manifest.capture_time_label.clone(),
        review_lineage,
    };
    record.validate()?;
    if &basis != deployment.current_anchor() {
        return Err(OriginalMediaExportError::AuthorityChanged);
    }
    checkpoint(cx, "original_media_export:metadata_verified")?;
    Ok((record, retained))
}

/// Read-only, exact whole-source preview. No file, retained export or delivery row is created.
pub fn preview_original_media_export(
    deployment: &ReferenceDeployment,
    request: &OriginalMediaExportRequest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<OriginalMediaExportPreview> {
    let (record, retained) = prepare_record(deployment, request, authority, cx)?;
    // This includes the original packet/wire graph for RTSP imports, not only the remux digest.
    if retained.verify_source(deployment, request.read_limits(), cx)? != record.source_digest {
        return Err(OriginalMediaExportError::CustodyMismatch);
    }
    let manifest = retained.manifest();
    let size = usize::try_from(record.source_bytes).map_err(|_| OriginalMediaExportError::Limit)?;
    let mut media_bytes = Vec::new();
    media_bytes
        .try_reserve_exact(size)
        .map_err(|_| OriginalMediaExportError::Limit)?;
    for (index, digest) in manifest.ordered_chunks.iter().enumerate() {
        checkpoint(cx, "original_media_export:source_chunk")?;
        let offset = (index as u64)
            .checked_mul(manifest.chunk_bytes)
            .ok_or(OriginalMediaExportError::Limit)?;
        let len = record
            .source_bytes
            .checked_sub(offset)
            .ok_or(OriginalMediaExportError::CustodyMismatch)?
            .min(manifest.chunk_bytes);
        let length = usize::try_from(len).map_err(|_| OriginalMediaExportError::Limit)?;
        let chunk = deployment
            .publisher()
            .spool()
            .read_bounded(*digest, length)?;
        if chunk.len() != length || ContentDigest::sha256(&chunk) != *digest {
            return Err(OriginalMediaExportError::CustodyMismatch);
        }
        if media_bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|n| n > size)
        {
            return Err(OriginalMediaExportError::Limit);
        }
        media_bytes.extend_from_slice(&chunk);
    }
    if media_bytes.len() != size || ContentDigest::sha256(&media_bytes) != record.source_digest {
        return Err(OriginalMediaExportError::CustodyMismatch);
    }
    if deployment.current_anchor() != &record.basis {
        return Err(OriginalMediaExportError::AuthorityChanged);
    }
    checkpoint(cx, "original_media_export:source_verified")?;
    let record_bytes = record.to_bytes();
    let manifest = ObjectManifest::new(
        record.profile(),
        [record.source_digest],
        Some(record.digest()),
    )?;
    Ok(OriginalMediaExportPreview {
        record,
        record_bytes,
        manifest_bytes: manifest.canonical_bytes(),
        root: manifest.root(),
        media_bytes,
    })
}

/// Recompute and approve the exact current package. This grants staging, never claims delivery.
pub fn approve_original_media_export(
    deployment: &ReferenceDeployment,
    request: &OriginalMediaExportRequest,
    approval: ContentDigest,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<PreparedOriginalMediaExport> {
    authorize(deployment, request, authority, cx, true)?;
    let preview = preview_original_media_export(deployment, request, authority, cx)?;
    if preview.approval() != approval {
        return Err(OriginalMediaExportError::StaleApproval);
    }
    checkpoint(cx, "original_media_export:approved")?;
    Ok(PreparedOriginalMediaExport { preview })
}

/// Revalidate a prepared package immediately before the adapter publishes its completion marker.
/// Keep the deployment's exclusive publication lease uninterrupted through staging and this check,
/// or use a freshly reopened owner whose lease remains held through completion. Rechecks event/source lineage, deletion,
/// privacy, principal/scope, expiry attestation, source/original custody and the entire head.
/// The caller must supply current authority and the lock-holding deployment owner, not a detached
/// cached snapshot. Reopening while the original owner still holds its lease is not required.
pub fn revalidate_original_media_export(
    deployment: &ReferenceDeployment,
    prepared: &PreparedOriginalMediaExport,
    authority: &ContextAuthority,
    cx: &ReplayCx,
) -> Result<()> {
    let preview = &prepared.preview;
    let request = preview.request();
    authorize(deployment, request, authority, cx, true)?;
    if deployment.current_anchor() != preview.basis() {
        return Err(OriginalMediaExportError::AuthorityChanged);
    }
    let (record, retained) = prepare_record(deployment, request, authority, cx)?;
    if record != preview.record {
        return Err(OriginalMediaExportError::StaleApproval);
    }
    if retained.verify_source(deployment, request.read_limits(), cx)? != record.source_digest {
        return Err(OriginalMediaExportError::CustodyMismatch);
    }
    checkpoint(cx, "original_media_export:output_revalidated")?;
    Ok(())
}

/// Verify exact package closure against an independently supplied root, without deployment or
/// network access. This verifies byte custody, not current authorization, expiry or scene truth.
pub fn verify_original_media_export(
    manifest_bytes: &[u8],
    record_bytes: &[u8],
    media_bytes: &[u8],
    expected_root: ContentDigest,
) -> Result<OriginalMediaExportRecord> {
    if !valid_digest(expected_root)
        || manifest_bytes.len() > 4096
        || record_bytes.len() > MAX_ORIGINAL_MEDIA_RECORD_BYTES
        || media_bytes.len() as u64 > MAX_ORIGINAL_MEDIA_BYTES
        || ContentDigest::sha256(manifest_bytes) != expected_root
    {
        return Err(OriginalMediaExportError::CustodyMismatch);
    }
    let manifest = ObjectManifest::from_canonical_bytes(manifest_bytes)?;
    let record = OriginalMediaExportRecord::from_bytes(record_bytes)?;
    let expected = ObjectManifest::new(
        record.profile(),
        [record.source_digest],
        Some(record.digest()),
    )?;
    if manifest != expected
        || manifest.root() != expected_root
        || media_bytes.len() as u64 != record.source_bytes
        || ContentDigest::sha256(media_bytes) != record.source_digest
    {
        return Err(OriginalMediaExportError::CustodyMismatch);
    }
    Ok(record)
}
