#![forbid(unsafe_code)]
//! Root-last custody and numerical replay of one complete long-recording sentinel run.
//!
//! The aggregate retains its exact model archive, complete execution recipe, full report and
//! ordinary package-detection child roots. Inspection proves custody, not numerical correctness.
//! Replay starts from the original whole decode range and compares every resulting identity;
//! an independently decodable child range is never assumed. Neither operation grants effects.

use std::collections::BTreeSet;
use std::fmt;

use fss_core::{
    BatchId, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError, EvidenceDelta, LedgerAnchor, ObjectId, Plane, SensorId, TimestampNs,
};
use fss_object::{HostSpoolIo, ObjectManifest, read_verified_payload};
use fss_publication::SlotName;

use super::recipe::{self, Recipe, digest, usize_value, valid_digest};
use super::{LongSentinelLimits, LongSentinelReport, run_long_sentinel_detection};
use crate::ingest::package_detect::sentinel::MAX_SENTINEL_BURST_FRAMES;
use crate::ingest::package_detect::{MAX_PACKAGE_DETECT_FRAMES, PackageDetectError};
use crate::ingest::package_event::{
    MAX_PACKAGE_ANALYSIS_BYTES, PackageDetectionRecord, PackageEventError,
    RetainedPackageDetection, RetentionStatus, retain_package_detection, source_validation,
};
use crate::ingest::privacy_mask::{PrivacyMaskError, current_mask};
use crate::ingest::recorded_decode::{RecordedDecodeError, source_capsule};
use crate::ingest::recorded_watch::WatchError;
use crate::ingest::rgb_package::{MAX_RGB_PACKAGE_BYTES, RgbDetectorPackage, RgbPackageError};
use crate::ingest::{FileIngestError, RetainedFileImport};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx, ScalarExecCx};

/// Canonical ledger payload of a retained aggregate; child formats remain unchanged.
pub const LONG_SENTINEL_RECORD_DOMAIN: &str = "fss.long_sentinel_record.v1";
/// Cognition-plane ledger family; this is derived evidence, never effect authority.
pub const LONG_SENTINEL_FAMILY: &str = "long_sentinel_detection";
/// Direct selected metadata ceiling, independent of native source and execution ceilings.
pub const MAX_LONG_SENTINEL_METADATA_BYTES: usize = 128 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_METADATA_OBJECTS: usize = 512;
const RECORD_POLICY: &[u8] =
    b"long-sentinel-custody-v1:complete-archive-recipe-report-child-roots:\
source-and-current-privacy-preflight:root-last:whole-range-numerical-replay:no-effect-authority";

pub(super) type Result<T> = std::result::Result<T, LongSentinelRetentionError>;

/// Current caller ceilings. Retained settings must fit without being replaced or relaxed.
#[derive(Clone, Copy, Debug)]
pub struct LongSentinelReplayLimits {
    /// Independent admission ceilings for the original exact native execution recipe.
    pub execution: LongSentinelLimits,
    /// Aggregate/recipe/archive/report and direct child manifest/record/report bytes read here,
    /// including the ordinary child reader's repeated direct metadata reads. Deployment open,
    /// retained-import metadata and original-source verification belong to their existing bounded
    /// custody owners, not to this metadata counter or the native replay's source-work counter.
    pub maximum_metadata_bytes: usize,
}
impl Default for LongSentinelReplayLimits {
    fn default() -> Self {
        Self {
            execution: LongSentinelLimits::default(),
            maximum_metadata_bytes: 64 * 1024 * 1024,
        }
    }
}
impl LongSentinelReplayLimits {
    /// Admit caller ceilings before reading selected metadata or model/source bytes.
    pub fn validate(&self) -> Result<()> {
        self.execution.validate()?;
        if !(1..=MAX_LONG_SENTINEL_METADATA_BYTES).contains(&self.maximum_metadata_bytes) {
            return Err(LongSentinelRetentionError::Limit);
        }
        Ok(())
    }
}

/// A refusal never returns a partial aggregate or a successful numerical verification.
#[derive(Debug)]
pub enum LongSentinelRetentionError {
    /// No complete aggregate authority names this exact report.
    Unavailable,
    /// Canonical metadata, model, report, schedule or child closure disagrees.
    InvalidRecord,
    /// Active context, durable authority or root visibility disagrees.
    AuthorityChanged,
    /// Current caller reservations do not admit the original complete recipe or metadata.
    Limit,
    /// Actual native replay differs from the saved aggregate or one of its child reports.
    Diverged,
    /// Cooperative cancellation; committed child custody can remain, but no success is invented.
    Cancelled,
    /// Existing package-event custody or privacy owner refused the operation.
    Package(Box<PackageEventError>),
    /// Existing whole-recording execution refused the operation.
    Detection(Box<PackageDetectError>),
    /// Existing source, canonical resource or publication owner refused the operation.
    Source(Box<WatchError>),
    /// Exact model-archive admission refused the operation.
    Model(Box<RgbPackageError>),
}
impl LongSentinelRetentionError {
    /// Reuse existing registered owner identities while retaining a specific local reason.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Unavailable => "ERR-PACKAGE-EVENT-UNAVAILABLE-001",
            Self::InvalidRecord | Self::Diverged => "ERR-PACKAGE-EVENT-MISMATCH-001",
            Self::Limit => "ERR-WATCH-LIMIT-001",
            Self::Cancelled => "ERR-PACKAGE-EVENT-CANCELLED-001",
            Self::AuthorityChanged => "ERR-PACKAGE-EVENT-001",
            Self::Package(error) => error.stable_id(),
            Self::Detection(error) => error.stable_id(),
            Self::Source(error) => error.stable_id(),
            Self::Model(error) => error.stable_id(),
        }
    }
}
impl fmt::Display for LongSentinelRetentionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("complete retained long-sentinel report unavailable"),
            Self::InvalidRecord => f.write_str("long-sentinel metadata or custody mismatch"),
            Self::AuthorityChanged => f.write_str("long-sentinel authority or root changed"),
            Self::Limit => {
                f.write_str("long-sentinel replay reservation or metadata bound exceeded")
            }
            Self::Diverged => {
                f.write_str("long-sentinel native replay differs from retained report")
            }
            Self::Cancelled => f.write_str("long-sentinel retention or replay cancelled"),
            Self::Package(error) => write!(f, "long-sentinel child custody: {error}"),
            Self::Detection(error) => write!(f, "long-sentinel execution: {error}"),
            Self::Source(error) => write!(f, "long-sentinel source: {error}"),
            Self::Model(error) => write!(f, "long-sentinel model: {error}"),
        }
    }
}
impl std::error::Error for LongSentinelRetentionError {}
impl From<ContractError> for LongSentinelRetentionError {
    fn from(_: ContractError) -> Self {
        Self::InvalidRecord
    }
}
impl From<PackageEventError> for LongSentinelRetentionError {
    fn from(error: PackageEventError) -> Self {
        Self::Package(Box::new(error))
    }
}
impl From<PackageDetectError> for LongSentinelRetentionError {
    fn from(error: PackageDetectError) -> Self {
        Self::Detection(Box::new(error))
    }
}
impl From<RgbPackageError> for LongSentinelRetentionError {
    fn from(error: RgbPackageError) -> Self {
        Self::Model(Box::new(error))
    }
}
impl From<WatchError> for LongSentinelRetentionError {
    fn from(error: WatchError) -> Self {
        Self::Source(Box::new(error))
    }
}
macro_rules! source_error {
    ($source:ty) => {
        impl From<$source> for LongSentinelRetentionError {
            fn from(error: $source) -> Self {
                WatchError::from(error).into()
            }
        }
    };
}
source_error!(ReferenceError);
source_error!(FileIngestError);
source_error!(RecordedDecodeError);
source_error!(fss_object::ObjectError);
source_error!(fss_object::SpoolError);
source_error!(fss_publication::LocalPublicationError);
impl From<PrivacyMaskError> for LongSentinelRetentionError {
    fn from(error: PrivacyMaskError) -> Self {
        PackageEventError::from(error).into()
    }
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| LongSentinelRetentionError::Cancelled)
}
fn check_context(deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
    checkpoint(cx, "long_sentinel_retained:begin")?;
    if cx.root_dir() != deployment.root() || !cx.io_authority().is_valid() {
        return Err(LongSentinelRetentionError::AuthorityChanged);
    }
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| LongSentinelRetentionError::AuthorityChanged)
}
fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn batch_id(report: ContentDigest) -> Result<BatchId> {
    Ok(BatchId::parse(format!(
        "batch:long-sentinel:{}",
        hex(report)
    ))?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Child {
    report: ContentDigest,
    record: ContentDigest,
    root: ContentDigest,
    first: usize,
    count: usize,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    report: ContentDigest,
    recipe: ContentDigest,
    package: ContentDigest,
    import: ContentDigest,
    import_root: ContentDigest,
    plan: ContentDigest,
    limits: ContentDigest,
    sensor: SensorId,
    privacy: ContentDigest,
    privacy_generation: Option<u64>,
    validity: CaptureInterval,
    children: Vec<Child>,
}
impl Record {
    fn validate(&self) -> Result<()> {
        for identity in [
            self.report,
            self.recipe,
            self.package,
            self.import,
            self.import_root,
            self.plan,
            self.limits,
            self.privacy,
        ] {
            valid_digest(identity)?;
        }
        if self.children.is_empty()
            || self.children.len() > MAX_PACKAGE_DETECT_FRAMES
            || self.privacy_generation == Some(0)
        {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        let mut prior_end = None;
        let mut reports = BTreeSet::new();
        let mut total = 0_usize;
        for child in &self.children {
            for identity in [child.report, child.record, child.root] {
                valid_digest(identity)?;
            }
            let end = child
                .first
                .checked_add(child.count)
                .ok_or(LongSentinelRetentionError::Limit)?;
            if child.count == 0
                || child.count > MAX_SENTINEL_BURST_FRAMES
                || prior_end.is_some_and(|prior| child.first < prior)
                || !reports.insert(child.report)
            {
                return Err(LongSentinelRetentionError::InvalidRecord);
            }
            total = total
                .checked_add(child.count)
                .ok_or(LongSentinelRetentionError::Limit)?;
            prior_end = Some(end);
        }
        if total > MAX_PACKAGE_DETECT_FRAMES {
            return Err(LongSentinelRetentionError::Limit);
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = CanonicalEncoder::new();
        e.text(LONG_SENTINEL_RECORD_DOMAIN);
        e.bytes(RECORD_POLICY);
        for identity in [
            self.report,
            self.recipe,
            self.package,
            self.import,
            self.import_root,
            self.plan,
            self.limits,
        ] {
            e.digest(identity);
        }
        e.text(self.sensor.as_str());
        e.digest(self.privacy);
        match self.privacy_generation {
            Some(generation) => {
                e.bool(true);
                e.u64(generation);
            }
            None => e.bool(false),
        }
        e.i128(self.validity.earliest.0);
        e.i128(self.validity.latest.0);
        e.u64(self.children.len() as u64);
        for child in &self.children {
            e.digest(child.report);
            e.digest(child.record);
            e.digest(child.root);
            e.u64(child.first as u64);
            e.u64(child.count as u64);
        }
        let bytes = e.finish_checked()?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(LongSentinelRetentionError::Limit);
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(LongSentinelRetentionError::Limit);
        }
        let mut d = CanonicalDecoder::new(bytes);
        if d.text()? != LONG_SENTINEL_RECORD_DOMAIN || d.bytes()? != RECORD_POLICY {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        let report = digest(&mut d)?;
        let recipe = digest(&mut d)?;
        let package = digest(&mut d)?;
        let import = digest(&mut d)?;
        let import_root = digest(&mut d)?;
        let plan = digest(&mut d)?;
        let limits = digest(&mut d)?;
        let sensor_text = d.text()?;
        if sensor_text.len() > 512 {
            return Err(LongSentinelRetentionError::Limit);
        }
        let sensor = SensorId::parse(sensor_text)?;
        let privacy = digest(&mut d)?;
        let privacy_generation = if d.bool()? { Some(d.u64()?) } else { None };
        let validity = CaptureInterval::new(TimestampNs(d.i128()?), TimestampNs(d.i128()?))?;
        let count = usize_value(&mut d)?;
        if count > MAX_PACKAGE_DETECT_FRAMES {
            return Err(LongSentinelRetentionError::Limit);
        }
        let mut children = Vec::with_capacity(count);
        for _ in 0..count {
            children.push(Child {
                report: digest(&mut d)?,
                record: digest(&mut d)?,
                root: digest(&mut d)?,
                first: usize_value(&mut d)?,
                count: usize_value(&mut d)?,
            });
        }
        d.ensure_finished()?;
        let value = Self {
            report,
            recipe,
            package,
            import,
            import_root,
            plan,
            limits,
            sensor,
            privacy,
            privacy_generation,
            validity,
            children,
        };
        if value.encode()? != bytes {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        Ok(value)
    }
    fn slot(&self) -> Result<SlotName> {
        SlotName::parse(&format!("ls-{}", hex(self.report)))
            .map_err(|_| LongSentinelRetentionError::InvalidRecord)
    }
    fn manifest(&self, record: ContentDigest) -> Result<ObjectManifest> {
        let mut children =
            BTreeSet::from([self.report, self.recipe, self.package, self.import_root]);
        children.extend(self.children.iter().map(|child| child.root));
        Ok(ObjectManifest::new(
            self.slot()?.as_str(),
            children,
            Some(record),
        )?)
    }
    fn delta(&self, record: ContentDigest, root: ContentDigest) -> Result<EvidenceDelta> {
        let id = hex(self.report);
        Ok(EvidenceDelta {
            delta_id: format!("delta:long-sentinel:{id}"),
            family: LONG_SENTINEL_FAMILY.to_owned(),
            object_id: ObjectId::parse(format!("object:long-sentinel:{id}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: self.validity,
            plane: Plane::Cognition,
            payload_digest: record,
            witness_digest: Some(root),
            operation_id: None,
        })
    }
    fn verify_recipe(&self, recipe: &Recipe) -> Result<()> {
        let plan = recipe.plan()?;
        let admitted: Vec<_> = plan
            .bursts()
            .iter()
            .filter(|burst| burst.admitted)
            .collect();
        if self.recipe != ContentDigest::sha256(&recipe.encode())
            || self.package != recipe.package
            || self.import != recipe.request.import_identity
            || self.plan != plan.digest()
            || self.limits != recipe.limits.digest()
            || self.children.len() != admitted.len()
            || self.children.iter().zip(admitted).any(|(child, burst)| {
                child.first != burst.first_segment || child.count != burst.segment_count
            })
        {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        Ok(())
    }
    fn verify_privacy(&self, deployment: &ReferenceDeployment) -> Result<()> {
        let mask = current_mask(deployment, &self.sensor)?;
        if mask.digest() != self.privacy || mask.generation() != self.privacy_generation {
            return Err(PrivacyMaskError::UnmaskedAccessRefused.into());
        }
        Ok(())
    }
    fn verify_source(
        &self,
        deployment: &ReferenceDeployment,
        recipe: &Recipe,
        cx: &ReplayCx,
    ) -> Result<()> {
        checkpoint(cx, "long_sentinel_retained:source")?;
        let retained =
            RetainedFileImport::open(deployment, self.import, recipe.limits.package.read, cx)?;
        let end = recipe
            .request
            .first_segment
            .checked_add(recipe.request.segment_count)
            .ok_or(LongSentinelRetentionError::Limit)?;
        if retained.import_root() != self.import_root
            || end > retained.manifest().segment_spans.len()
        {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        // Native cold replay needs the original capsule for every requested source segment,
        // including an unsampled reference picture. Verify their exact retained delta/span
        // bindings now so a missing late capsule cannot follow newly published child roots.
        for segment in recipe.request.first_segment..end {
            checkpoint(cx, "long_sentinel_retained:source_capsule")?;
            let (capsule, _) = source_capsule(deployment, &retained, segment)?;
            if capsule.sensor_id != self.sensor {
                return Err(LongSentinelRetentionError::InvalidRecord);
            }
        }
        // Verify all original custody, including a late unselected suffix and native acquisition
        // provenance. This is the existing independent custody pass, not a refilled decode budget.
        retained.verify_source(deployment, recipe.limits.package.read, cx)?;
        Ok(())
    }
}

struct MetadataReader {
    remaining: usize,
    objects: usize,
}
impl MetadataReader {
    fn charge(&mut self, bytes: usize, objects: usize) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(LongSentinelRetentionError::Limit)?;
        self.objects = self
            .objects
            .checked_add(objects)
            .ok_or(LongSentinelRetentionError::Limit)?;
        if self.objects > MAX_METADATA_OBJECTS {
            return Err(LongSentinelRetentionError::Limit);
        }
        Ok(())
    }
    fn read(
        &mut self,
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        maximum: usize,
        cx: &ReplayCx,
    ) -> Result<Vec<u8>> {
        checkpoint(cx, "long_sentinel_retained:metadata")?;
        valid_digest(identity)?;
        if self.remaining == 0 || self.objects == MAX_METADATA_OBJECTS {
            return Err(LongSentinelRetentionError::Limit);
        }
        let bytes = read_verified_payload(
            deployment.publisher().spool().root(),
            identity,
            maximum.min(self.remaining),
            &HostSpoolIo,
        )?;
        self.charge(bytes.len(), 1)?;
        Ok(bytes)
    }
}

/// Custody-backed aggregate metadata. This type is not a claim that inference has been rerun.
#[derive(Clone, Debug)]
pub struct RetainedLongSentinel {
    record: Record,
    recipe: Recipe,
    archive: Vec<u8>,
    report_json: Vec<u8>,
    root: ContentDigest,
    anchor: LedgerAnchor,
    status: RetentionStatus,
    child_reports: Vec<ContentDigest>,
}
impl RetainedLongSentinel {
    /// Read complete aggregate/child custody under independent current ceilings. Missing bytes
    /// are never repaired from loose files, nor is changed privacy accepted through a later head.
    pub fn open(
        deployment: &ReferenceDeployment,
        report_digest: ContentDigest,
        limits: &LongSentinelReplayLimits,
        cx: &ReplayCx,
    ) -> Result<Self> {
        limits.validate()?;
        check_context(deployment, cx)?;
        valid_digest(report_digest)?;
        let target = batch_id(report_digest)?;
        let batch = deployment
            .ledger()
            .batches()
            .iter()
            .find(|batch| batch.batch_id == target)
            .ok_or(LongSentinelRetentionError::Unavailable)?;
        let [delta] = batch.deltas.as_slice() else {
            return Err(LongSentinelRetentionError::InvalidRecord);
        };
        let mut reader = MetadataReader {
            remaining: limits.maximum_metadata_bytes,
            objects: 0,
        };
        let bytes = reader.read(deployment, delta.payload_digest, MAX_RECORD_BYTES, cx)?;
        let record = Record::decode(&bytes)?;
        if record.report != report_digest {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        let recipe =
            Recipe::decode(&reader.read(deployment, record.recipe, recipe::MAX_BYTES, cx)?)?;
        recipe.validate_within(&limits.execution)?;
        record.verify_recipe(&recipe)?;
        record.verify_privacy(deployment)?;
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
            || reader.read(deployment, root, MAX_RECORD_BYTES, cx)? != manifest.canonical_bytes()
        {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        let report_json = reader.read(
            deployment,
            record.report,
            recipe.limits.maximum_report_bytes,
            cx,
        )?;
        let archive = reader.read(deployment, record.package, MAX_RGB_PACKAGE_BYTES, cx)?;
        for child in &record.children {
            checkpoint(cx, "long_sentinel_retained:child")?;
            let child_bytes =
                reader.read(deployment, child.record, MAX_PACKAGE_ANALYSIS_BYTES, cx)?;
            let child_record = PackageDetectionRecord::decode(&child_bytes)?;
            verify_child(&record, &recipe, child, &child_record)?;
            let manifest = child_record.manifest(child.record)?;
            let manifest_bytes = reader.read(deployment, child.root, MAX_RECORD_BYTES, cx)?;
            let report_bytes =
                reader.read(deployment, child.report, MAX_PACKAGE_ANALYSIS_BYTES, cx)?;
            if manifest.root() != child.root || manifest_bytes != manifest.canonical_bytes() {
                return Err(LongSentinelRetentionError::InvalidRecord);
            }
            // The unchanged ordinary reader repeats these three direct reads while proving its
            // own ledger/root/privacy/source contracts. Reserve them before invoking that owner.
            reader.charge(
                child_bytes
                    .len()
                    .checked_add(manifest_bytes.len())
                    .and_then(|n| n.checked_add(report_bytes.len()))
                    .ok_or(LongSentinelRetentionError::Limit)?,
                3,
            )?;
            let retained = RetainedPackageDetection::open(deployment, child.report, cx)?;
            if retained.record() != &child_record
                || retained.record_digest() != child.record
                || retained.root() != child.root
            {
                return Err(LongSentinelRetentionError::InvalidRecord);
            }
        }
        record.verify_source(deployment, &recipe, cx)?;
        check_context(deployment, cx)?;
        checkpoint(cx, "long_sentinel_retained:complete")?;
        let child_reports = record.children.iter().map(|child| child.report).collect();
        Ok(Self {
            record,
            recipe,
            archive,
            report_json,
            root,
            anchor: batch.new_anchor.clone(),
            status: RetentionStatus::AlreadyRetained,
            child_reports,
        })
    }
    /// Exact aggregate report identity, also the stable lookup handle.
    pub const fn report_digest(&self) -> ContentDigest {
        self.record.report
    }
    /// Root binding the complete source/model/recipe/report/child closure.
    pub const fn root(&self) -> ContentDigest {
        self.root
    }
    /// Complete canonical execution recipe identity.
    pub const fn recipe_digest(&self) -> ContentDigest {
        self.record.recipe
    }
    /// Exact archived model package identity.
    pub const fn package_digest(&self) -> ContentDigest {
        self.record.package
    }
    /// Ordered ordinary package-report handles, each independently usable by the event path.
    pub fn child_reports(&self) -> &[ContentDigest] {
        &self.child_reports
    }
    /// Whether this call created the complete aggregate or reopened an identical one.
    pub const fn status(&self) -> RetentionStatus {
        self.status
    }
    /// Canonical aggregate retention anchor, never an inference or effect authorization.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
}

fn verify_child(
    record: &Record,
    recipe: &Recipe,
    child: &Child,
    value: &PackageDetectionRecord,
) -> Result<()> {
    if value.report_digest != child.report
        || value.package_digest != record.package
        || value.manifest_digest != recipe.manifest
        || value.model_digest != recipe.model
        || value.graph_digest != recipe.graph
        || value.contract_digest != recipe.contract
        || value.import_identity != record.import
        || value.import_root != record.import_root
        || value.first_segment != child.first as u64
        || value.segment_count != child.count as u64
        || value
            .frames
            .iter()
            .any(|frame| frame.sensor_id != record.sensor.as_str())
    {
        return Err(LongSentinelRetentionError::InvalidRecord);
    }
    Ok(())
}

/// Retain a completed private-construction report and the exact verified archive. Every child's
/// source/privacy closure and all original source bytes are checked before the first new write.
/// Child roots can survive cancellation; only the final aggregate batch certifies completion.
pub fn retain_long_sentinel_detection(
    deployment: &mut ReferenceDeployment,
    package: &RgbDetectorPackage,
    archive_bytes: &[u8],
    report: &LongSentinelReport,
    cx: &ReplayCx,
) -> Result<RetainedLongSentinel> {
    check_context(deployment, cx)?;
    if archive_bytes.len() > MAX_RGB_PACKAGE_BYTES
        || ContentDigest::sha256(archive_bytes) != package.archive_digest()
        || ContentDigest::sha256(report.json().as_bytes()) != report.digest()
        || report.json().len() > report.limits().maximum_report_bytes
    {
        return Err(LongSentinelRetentionError::InvalidRecord);
    }
    let recipe = Recipe::new(package, report.request(), report.config(), report.limits())?;
    if recipe.plan()?.digest() != report.plan().digest() {
        return Err(LongSentinelRetentionError::InvalidRecord);
    }
    let first = report
        .reports()
        .first()
        .ok_or(LongSentinelRetentionError::InvalidRecord)?;
    let first_frame = first
        .frames
        .first()
        .ok_or(LongSentinelRetentionError::InvalidRecord)?;
    let mut record = Record {
        report: report.digest(),
        recipe: ContentDigest::sha256(&recipe.encode()),
        package: package.archive_digest(),
        import: report.request().import_identity,
        import_root: first.import_root,
        plan: report.plan().digest(),
        limits: report.limits().digest(),
        sensor: first_frame.capsule.sensor_id.clone(),
        privacy: first.privacy.digest(),
        privacy_generation: first.privacy.generation(),
        validity: first_frame.capsule.capture,
        children: Vec::with_capacity(report.reports().len()),
    };
    record.verify_privacy(deployment)?;
    for child_report in report.reports() {
        checkpoint(cx, "long_sentinel_retained:preflight_child")?;
        if child_report.digest != ContentDigest::sha256(child_report.json.as_bytes())
            || child_report.privacy.digest() != record.privacy
            || child_report.privacy.generation() != record.privacy_generation
            || child_report
                .frames
                .iter()
                .any(|f| f.detections.contract_digest() != recipe.contract)
        {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        let child_record = PackageDetectionRecord::from_report(package, child_report)?;
        let child_digest = ContentDigest::sha256(&child_record.encode()?);
        let manifest = child_record.manifest(child_digest)?;
        let child = Child {
            report: child_report.digest,
            record: child_digest,
            root: manifest.root(),
            first: child_report.first_segment,
            count: child_report.segment_count,
        };
        verify_child(&record, &recipe, &child, &child_record)?;
        source_validation::verify_report_privacy(
            &child_record,
            child_report.json.as_bytes(),
            &current_mask(deployment, &record.sensor)?,
        )?;
        source_validation::verify_sources(deployment, &child_record, cx)?;
        if deployment
            .publisher()
            .root(&child_record.slot()?)
            .is_some_and(|r| r.root != child.root)
        {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        let child_target = child_record.batch_id()?;
        if deployment
            .ledger()
            .batches()
            .iter()
            .any(|batch| batch.batch_id == child_target)
        {
            let existing = RetainedPackageDetection::open(deployment, child.report, cx)?;
            if existing.record() != &child_record || existing.root() != child.root {
                return Err(LongSentinelRetentionError::InvalidRecord);
            }
        }
        let validity = child_record.validity()?;
        record.validity = CaptureInterval::new(
            record.validity.earliest.min(validity.earliest),
            record.validity.latest.max(validity.latest),
        )?;
        record.children.push(child);
    }
    record.validate()?;
    record.verify_recipe(&recipe)?;
    record.verify_source(deployment, &recipe, cx)?;
    let bytes = record.encode()?;
    let record_digest = ContentDigest::sha256(&bytes);
    let manifest = record.manifest(record_digest)?;
    let target = batch_id(record.report)?;
    if deployment
        .ledger()
        .batches()
        .iter()
        .any(|batch| batch.batch_id == target)
    {
        let retained = RetainedLongSentinel::open(
            deployment,
            record.report,
            &LongSentinelReplayLimits {
                execution: recipe.limits,
                maximum_metadata_bytes: MAX_LONG_SENTINEL_METADATA_BYTES,
            },
            cx,
        )?;
        if retained.record != record {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
        return Ok(retained);
    }
    let slot = record.slot()?;
    let existing_root = deployment.publisher().root(&slot).map(|root| root.root);
    if existing_root.is_some_and(|root| root != manifest.root()) {
        return Err(LongSentinelRetentionError::InvalidRecord);
    }
    check_context(deployment, cx)?;
    checkpoint(cx, "long_sentinel_retained:preflight_complete")?;
    for (child_report, child) in report.reports().iter().zip(&record.children) {
        let retained = retain_package_detection(deployment, package, child_report, cx)?;
        if retained.root() != child.root || retained.record_digest() != child.record {
            return Err(LongSentinelRetentionError::InvalidRecord);
        }
    }
    let recipe_bytes = recipe.encode();
    for object in [
        archive_bytes,
        recipe_bytes.as_slice(),
        report.json().as_bytes(),
        bytes.as_slice(),
    ] {
        checkpoint(cx, "long_sentinel_retained:stage")?;
        let identity = deployment.publisher_mut().stage_object(object)?;
        deployment.publisher_mut().verify_object(identity)?;
    }
    for identity in manifest.children() {
        checkpoint(cx, "long_sentinel_retained:closure")?;
        deployment.publisher_mut().verify_object(*identity)?;
    }
    if existing_root.is_none() {
        deployment
            .publisher_mut()
            .stage_manifest(&slot, &manifest)?;
    }
    deployment.publish_and_commit(&slot, &manifest, record.validity, cx)?;
    checkpoint(cx, "long_sentinel_retained:commit")?;
    let mut children = manifest.children().to_vec();
    children.push(manifest.root());
    let anchor = deployment.append_batch(
        target,
        vec![record.delta(record_digest, manifest.root())?],
        children,
        cx,
    )?;
    cx.checkpoint_post_commit("long_sentinel_retained:retained");
    let child_reports = record.children.iter().map(|child| child.report).collect();
    Ok(RetainedLongSentinel {
        record,
        recipe,
        archive: archive_bytes.to_vec(),
        report_json: report.json().as_bytes().to_vec(),
        root: manifest.root(),
        anchor,
        status: RetentionStatus::Retained,
        child_reports,
    })
}

/// Numerically rerun the original complete native source range from retained model and source
/// custody. No model/source pathname is accepted, no child range is independently decoded,
/// and no caller ceiling silently replaces a saved setting. No writes or effects occur.
pub fn rerun_long_sentinel_detection(
    deployment: &ReferenceDeployment,
    report_digest: ContentDigest,
    limits: &LongSentinelReplayLimits,
    cx: &ReplayCx,
    scalar: &ScalarExecCx,
) -> Result<LongSentinelReport> {
    checkpoint(cx, "long_sentinel_replay:begin")?;
    let retained = RetainedLongSentinel::open(deployment, report_digest, limits, cx)?;
    let recipe = &retained.recipe;
    let package = RgbDetectorPackage::load_with_backend(
        &retained.archive,
        recipe.package,
        recipe.import_work_units(),
        recipe.backend,
        cx,
        scalar,
    )?;
    recipe.verify_package(&package)?;
    checkpoint(cx, "long_sentinel_replay:execute")?;
    let report = run_long_sentinel_detection(
        deployment,
        &package,
        &recipe.request,
        recipe.config,
        &recipe.limits,
        cx,
        scalar,
    )?;
    if report.digest() != retained.record.report
        || report.json().as_bytes() != retained.report_json
        || report.plan().digest() != retained.record.plan
        || report.reports().len() != retained.record.children.len()
        || report
            .reports()
            .iter()
            .zip(&retained.record.children)
            .any(|(actual, expected)| actual.digest != expected.report)
    {
        return Err(LongSentinelRetentionError::Diverged);
    }
    checkpoint(cx, "long_sentinel_replay:complete")?;
    Ok(report)
}
