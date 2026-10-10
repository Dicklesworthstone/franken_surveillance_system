#![forbid(unsafe_code)]
//! Cold inspection and native replay of published whole-recording entry and corroboration events.
//!
//! Inspection checks the current event, retained metadata, exact source-capsule payloads and
//! current privacy lineage. It does not run perception or certify the retained measurements.
//! Replay additionally executes the native owner and compares every complete camera analysis
//! and the selected event/provenance. Neither operation publishes, repairs or dispatches anything.
//! Only original revision-one profiles are supported; reviewed successors remain explicit refusals.

use std::fmt;

use fss_core::{
    CanonicalDecode, CanonicalEncode, ContentDigest, ContractError, DigestAlgorithm, EventHypothesis,
    EventId, EventKind, LedgerAnchor, ObjectId, SensorId,
};
use fss_object::{HostSpoolIo, ObjectManifest, read_verified_payload};
use fss_publication::{ROOT_REACHABILITY_FAMILY, SlotName};

use super::long_dwell::{LongDwellLimits, MAX_LONG_DWELL_FRAMES, MAX_LONG_DWELL_TRACE_BYTES};
use super::long_watch::LongWatchReport;
use super::privacy_mask::current_mask;
use super::recorded_corroboration::{CorroborationError, CorroborationStatus};
use super::recorded_corroboration::streaming::LongCorroborationRecipe;
use super::recorded_decode::{RecordedDecodeError, MAX_RECORDED_DECODE_RECEIPT_BYTES, source_capsule};
use super::recorded_watch::{WatchError, WatchStatus};
use super::{FileIngestError, RetainedFileImport};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

mod watch;
mod corroboration;
pub use watch::WatchReplayRecipe;

/// Maximum complete analysis payload, including its existing bounded trace.
pub const MAX_LONG_EVENT_ANALYSIS_BYTES: usize = MAX_LONG_DWELL_TRACE_BYTES + 256 * 1024;
/// Maximum selected metadata bytes, including all selected source-capsule payloads.
pub const MAX_LONG_EVENT_METADATA_BYTES: usize = 256 * 1024 * 1024;
const MAX_METADATA_OBJECTS: usize = MAX_LONG_DWELL_FRAMES * 4 + 1024;
const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
type Result<T> = std::result::Result<T, LongEventReplayError>;

/// Explicit admission ceilings. Execution limits are reserved independently for each camera.
#[derive(Clone, Copy, Debug)]
pub struct LongEventReplayLimits {
    /// Ceiling on the retained recipe's reservations and native decoder/source work per camera.
    pub execution: LongDwellLimits,
    /// Cumulative selected payload reads, including the current-event and source-capsule
    /// owners' second verification reads. Deployment/import opening, privacy-owner lookups and
    /// native source-chunk reads retain their separate existing bounds.
    pub maximum_metadata_bytes: usize,
}
impl Default for LongEventReplayLimits {
    fn default() -> Self {
        Self {
            execution: LongDwellLimits::default(),
            maximum_metadata_bytes: 64 * 1024 * 1024,
        }
    }
}
impl LongEventReplayLimits {
    /// Reject invalid ceilings before reading retained metadata or executing perception.
    pub fn validate(&self) -> Result<()> {
        self.execution.validate()?;
        if !(1..=MAX_LONG_EVENT_METADATA_BYTES).contains(&self.maximum_metadata_bytes) {
            return Err(LongEventReplayError::Limit);
        }
        Ok(())
    }
}

/// Explicit current selection, independent of the command's request to execute perception.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongEventReplayPins {
    /// Exact original event revision.
    pub event_revision: ContentDigest,
    /// Current candidate-provenance root, containing all one- or two-camera analysis roots.
    /// A corroboration policy fingerprint is not this root.
    pub provenance_root: ContentDigest,
}

/// A failed inspection or replay never returns a successful verification object.
#[derive(Debug)]
pub enum LongEventReplayError {
    /// Retained bytes or cross-record bindings violate the selected profile.
    InvalidRecord,
    /// Unsupported event family, revision, or stored computation profile.
    UnsupportedProfile,
    /// Caller pins no longer name the current event/provenance.
    StaleSelection,
    /// The current privacy generation differs from the original analysis.
    PrivacyChanged,
    /// Authority head, current event, or visible root changed or is incoherent.
    AuthorityChanged,
    /// Native execution differs from the original complete analysis or event.
    Diverged,
    /// A metadata or computation reservation exceeds its explicit ceiling.
    Limit,
    /// Cooperative cancellation; no successful verification is returned.
    Cancelled,
    /// Existing single-camera custody or execution owner refused.
    Source(Box<WatchError>),
    /// Existing two-camera owner refused.
    Corroboration(Box<CorroborationError>),
}
impl LongEventReplayError {
    /// Stable reason within the existing watch/corroboration error families.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRecord => "invalid_long_event_replay_record",
            Self::UnsupportedProfile => "unsupported_long_event_replay_profile",
            Self::StaleSelection => "long_event_replay_selection_changed",
            Self::PrivacyChanged => "long_event_replay_privacy_changed",
            Self::AuthorityChanged => "long_event_replay_authority_changed",
            Self::Diverged => "long_event_native_replay_diverged",
            Self::Limit => "long_event_replay_bound_exceeded",
            Self::Cancelled => "long_event_replay_cancelled",
            Self::Source(_) | Self::Corroboration(_) => "long_event_replay_owner_refusal",
        }
    }
    /// Registered error family; the reason preserves the replay-specific classification.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Limit => "ERR-WATCH-LIMIT-001",
            Self::Source(error) => error.stable_id(),
            Self::Corroboration(error) => error.stable_id(),
            _ => "ERR-WATCH-001",
        }
    }
}
impl fmt::Display for LongEventReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stable_id(), self.reason())?;
        match self {
            Self::Source(error) => write!(f, ": {error}"),
            Self::Corroboration(error) => write!(f, ": {error}"),
            _ => Ok(()),
        }
    }
}
impl std::error::Error for LongEventReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error.as_ref()),
            Self::Corroboration(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
impl From<ContractError> for LongEventReplayError {
    fn from(_: ContractError) -> Self { Self::InvalidRecord }
}
impl From<WatchError> for LongEventReplayError {
    fn from(error: WatchError) -> Self { Self::Source(Box::new(error)) }
}
impl From<CorroborationError> for LongEventReplayError {
    fn from(error: CorroborationError) -> Self { Self::Corroboration(Box::new(error)) }
}
macro_rules! source_error {
    ($error:ty) => {
        impl From<$error> for LongEventReplayError {
            fn from(error: $error) -> Self { WatchError::from(error).into() }
        }
    };
}
source_error!(ReferenceError);
source_error!(FileIngestError);
source_error!(RecordedDecodeError);
source_error!(fss_object::SpoolError);

/// Retained owner configuration, distinct from replay execution authority.
#[derive(Clone, Debug)]
pub enum LongEventReplayRecipe {
    /// Whole-recording image-zone entry recipe. Codec/read safety ceilings were not all retained
    /// by this historical format; those are current caller bounds, explicitly marked by the type.
    Watch(WatchReplayRecipe),
    /// Complete retained two-camera recipe, including original native codec/read ceilings.
    Corroboration(LongCorroborationRecipe),
}

/// Metadata and capsule inspection, deliberately distinct from verified native replay.
#[derive(Debug)]
pub struct LongEventReplayInspection {
    event: EventHypothesis,
    event_root: ContentDigest,
    pins: LongEventReplayPins,
    recipe: LongEventReplayRecipe,
    analysis_roots: Vec<ContentDigest>,
    analysis_digests: Vec<ContentDigest>,
    basis: LedgerAnchor,
    metadata_bytes: usize,
}
impl LongEventReplayInspection {
    /// Current original event, read through its guarded authority owner.
    pub fn event(&self) -> &EventHypothesis { &self.event }
    /// Current authoritative event-revision publication root.
    pub const fn event_root(&self) -> ContentDigest { self.event_root }
    /// Selection required before native replay.
    pub const fn pins(&self) -> LongEventReplayPins { self.pins }
    /// Supported computation family, not an event's physical interpretation.
    pub fn profile(&self) -> &'static str {
        match &self.recipe {
            LongEventReplayRecipe::Watch(_) => "long_watch",
            LongEventReplayRecipe::Corroboration(_) => "long_corroboration",
        }
    }
    /// Reconstructed original settings. These never confer publication or effect authority.
    pub fn recipe(&self) -> &LongEventReplayRecipe { &self.recipe }
    /// Complete source-analysis roots, in retained camera order.
    pub fn analysis_roots(&self) -> &[ContentDigest] { &self.analysis_roots }
    /// Complete retained native trace payload identities, in retained camera order.
    pub fn analysis_digests(&self) -> &[ContentDigest] { &self.analysis_digests }
    /// One exact authority snapshot consumed by this read.
    pub fn basis(&self) -> &LedgerAnchor { &self.basis }
    /// Cumulative selected metadata and source-capsule payload bytes actually fetched here.
    pub const fn metadata_bytes_read(&self) -> usize { self.metadata_bytes }
}

/// Constructible only after the original native computation reproduces every selected digest.
#[derive(Debug)]
pub struct VerifiedLongEventReplay {
    inspection: LongEventReplayInspection,
    frames: usize,
    source_bytes: u64,
}
impl VerifiedLongEventReplay {
    /// Original inspected selection, now reproduced by native execution.
    pub fn inspection(&self) -> &LongEventReplayInspection { &self.inspection }
    /// Sum of successfully decoded native frames across all participating cameras.
    pub const fn frames_replayed(&self) -> usize { self.frames }
    /// Sum of actual native source-chunk reads across all participating cameras.
    pub const fn source_chunk_bytes_read(&self) -> u64 { self.source_bytes }
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage).map_err(|_| LongEventReplayError::Cancelled)
}
fn valid_digest(value: ContentDigest) -> Result<()> {
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(LongEventReplayError::InvalidRecord);
    }
    Ok(())
}
fn hex(value: ContentDigest) -> String {
    value.bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}
fn check_context(deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
    checkpoint(cx, "long_event_replay:read")?;
    if cx.root_dir() != deployment.root() || !cx.io_authority().is_valid() {
        return Err(LongEventReplayError::AuthorityChanged);
    }
    deployment.ledger().verify_durable_head()
        .map_err(|_| LongEventReplayError::AuthorityChanged)
}
fn unchanged(deployment: &ReferenceDeployment, basis: &LedgerAnchor, cx: &ReplayCx) -> Result<()> {
    check_context(deployment, cx)?;
    if deployment.current_anchor() != basis {
        return Err(LongEventReplayError::AuthorityChanged);
    }
    Ok(())
}

struct MetadataReader {
    remaining: usize,
    used: usize,
    objects: usize,
}
impl MetadataReader {
    // Reserve a known, content-addressed owner read before it runs. On success its length must
    // equal the copy already verified here; a refusal produces no successful read counters.
    fn reserve_owner_read(&mut self, length: usize) -> Result<()> {
        if self.objects == MAX_METADATA_OBJECTS || length > self.remaining {
            return Err(LongEventReplayError::Limit);
        }
        self.objects += 1;
        self.remaining -= length;
        self.used = self.used.checked_add(length).ok_or(LongEventReplayError::Limit)?;
        Ok(())
    }
    fn read(&mut self, deployment: &ReferenceDeployment, digest: ContentDigest, maximum: usize, cx: &ReplayCx) -> Result<Vec<u8>> {
        checkpoint(cx, "long_event_replay:metadata")?;
        valid_digest(digest)?;
        if self.objects == MAX_METADATA_OBJECTS || self.remaining == 0 {
            return Err(LongEventReplayError::Limit);
        }
        let bytes = read_verified_payload(
            deployment.publisher().spool().root(), digest, maximum.min(self.remaining), &HostSpoolIo,
        )?;
        self.reserve_owner_read(bytes.len())?;
        checkpoint(cx, "long_event_replay:metadata_read")?;
        Ok(bytes)
    }
}
fn manifest(bytes: &[u8], kind: &str, maximum: usize, metadata: bool) -> Result<ObjectManifest> {
    let value = ObjectManifest::from_canonical_bytes(bytes)
        .map_err(|_| LongEventReplayError::InvalidRecord)?;
    if value.kind() != kind || value.metadata_digest().is_some() != metadata
        || value.children().len() > maximum {
        return Err(LongEventReplayError::InvalidRecord);
    }
    Ok(value)
}
fn published_root(deployment: &ReferenceDeployment, slot: &SlotName) -> Result<ContentDigest> {
    let object = ObjectId::parse(format!("object:local-root:{}", slot.as_str()))?;
    let current = deployment.ledger().current().objects.get(&object)
        .ok_or(LongEventReplayError::AuthorityChanged)?;
    let visible = deployment.publisher().root(slot)
        .ok_or(LongEventReplayError::AuthorityChanged)?;
    if current.family != ROOT_REACHABILITY_FAMILY || current.generation != 1
        || current.payload_digest != visible.root {
        return Err(LongEventReplayError::AuthorityChanged);
    }
    Ok(visible.root)
}
fn slot(prefix: &str, digest: ContentDigest) -> Result<SlotName> {
    SlotName::parse(&format!("{prefix}-{}", hex(digest)))
        .map_err(|_| LongEventReplayError::InvalidRecord)
}
fn event_identity(event: &EventId, prefix: &str) -> Result<ContentDigest> {
    let suffix = event.as_str().strip_prefix(prefix)
        .ok_or(LongEventReplayError::UnsupportedProfile)?;
    if suffix.len() != 64 || !suffix.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(LongEventReplayError::InvalidRecord);
    }
    Ok(ContentDigest::parse(format!("sha256:{suffix}"))?)
}

#[derive(Clone, Debug)]
struct SourceBinding {
    import_identity: ContentDigest,
    import_root: ContentDigest,
    manifest: ContentDigest,
    anchor: LedgerAnchor,
    sensor: SensorId,
    privacy: ContentDigest,
    privacy_generation: Option<u64>,
    media_format: String,
    first: usize,
    count: usize,
}
fn verify_source_metadata(
    deployment: &ReferenceDeployment, source: &SourceBinding,
    limits: &LongEventReplayLimits, reader: &mut MetadataReader, cx: &ReplayCx,
) -> Result<()> {
    checkpoint(cx, "long_event_replay:source")?;
    let privacy = current_mask(deployment, &source.sensor).map_err(RecordedDecodeError::from)?;
    if privacy.digest() != source.privacy || privacy.generation() != source.privacy_generation {
        return Err(LongEventReplayError::PrivacyChanged);
    }
    let retained = RetainedFileImport::open(deployment, source.import_identity, limits.execution.decode.read_limits, cx)?;
    if retained.import_root() != source.import_root || retained.manifest_digest() != source.manifest
        || retained.authority_anchor() != &source.anchor || retained.manifest().format != source.media_format
        || retained.manifest().capture_time_label != "operator_assumption" {
        return Err(LongEventReplayError::InvalidRecord);
    }
    let end = source.first.checked_add(source.count).ok_or(LongEventReplayError::Limit)?;
    if source.count == 0 || source.count > MAX_LONG_DWELL_FRAMES || end > retained.manifest().segment_spans.len() {
        return Err(LongEventReplayError::InvalidRecord);
    }
    for segment in source.first..end {
        checkpoint(cx, "long_event_replay:capsule")?;
        let span = &retained.manifest().segment_spans[segment];
        let object = ObjectId::parse(format!("object:capsule:{}", span.capsule_id.as_str()))?;
        let current = deployment.ledger().current().objects.get(&object)
            .ok_or(LongEventReplayError::AuthorityChanged)?;
        if current.family != "sensor_capsule" || current.generation != 1 {
            return Err(LongEventReplayError::AuthorityChanged);
        }
        let bytes = reader.read(deployment, current.payload_digest, MAX_RECORDED_DECODE_RECEIPT_BYTES, cx)?;
        reader.reserve_owner_read(bytes.len())?;
        let (capsule, digest) = source_capsule(deployment, &retained, segment)?;
        if digest != current.payload_digest {
            return Err(LongEventReplayError::AuthorityChanged);
        }
        if capsule.sensor_id != source.sensor || bytes != capsule.try_canonical_bytes()? {
            return Err(LongEventReplayError::InvalidRecord);
        }
    }
    Ok(())
}

struct LoadedProfile {
    recipe: LongEventReplayRecipe,
    analysis_roots: Vec<ContentDigest>,
    analysis_digests: Vec<ContentDigest>,
    sources: Vec<SourceBinding>,
}
fn load(
    deployment: &ReferenceDeployment, event_id: &EventId, pins: Option<LongEventReplayPins>,
    limits: &LongEventReplayLimits, cx: &ReplayCx,
) -> Result<LongEventReplayInspection> {
    limits.validate()?;
    check_context(deployment, cx)?;
    let basis = deployment.current_anchor().clone();
    let (prefix, kind) = if event_id.as_str().starts_with("event:long-watch:") {
        ("lw-e", "long_watch")
    } else if event_id.as_str().starts_with("event:long-corroborated:") {
        ("lc", "long_corroboration")
    } else {
        return Err(LongEventReplayError::UnsupportedProfile);
    };
    if let Some(pins) = pins {
        valid_digest(pins.event_revision)?;
        valid_digest(pins.provenance_root)?;
    }
    let mut reader = MetadataReader { remaining: limits.maximum_metadata_bytes, used: 0, objects: 0 };
    // Bound the selected authority payloads before entering the existing authority reader.
    // Reviewed successors are not silently reinterpreted as the original source computation.
    let object = ObjectId::parse(format!("object:event:{}", event_id.as_str()))?;
    let current = deployment.ledger().current().objects.get(&object)
        .ok_or(LongEventReplayError::AuthorityChanged)?;
    if current.family != "event_revision" {
        return Err(LongEventReplayError::AuthorityChanged);
    }
    if current.generation != 1 {
        return Err(LongEventReplayError::UnsupportedProfile);
    }
    let event_root_bytes = reader.read(deployment, current.payload_digest, MAX_MANIFEST_BYTES, cx)?;
    let event_manifest = ObjectManifest::from_canonical_bytes(&event_root_bytes)
        .map_err(|_| LongEventReplayError::InvalidRecord)?;
    if event_manifest.children().len() > 512 {
        return Err(LongEventReplayError::Limit);
    }
    let event_payload = event_manifest.metadata_digest().ok_or(LongEventReplayError::InvalidRecord)?;
    let bytes = reader.read(deployment, event_payload, 512 * 1024, cx)?;
    for &child in event_manifest.children() {
        let _ = reader.read(deployment, child, MAX_LONG_EVENT_ANALYSIS_BYTES, cx)?;
    }
    let parsed = EventHypothesis::from_canonical_bytes(&bytes)
        .map_err(|_| LongEventReplayError::InvalidRecord)?;
    if parsed.revision != 1 || parsed.supersedes.is_some() || parsed.kind != EventKind::Unclassified {
        return Err(LongEventReplayError::UnsupportedProfile);
    }
    // The current-event owner also visits this revision while enumerating prior revisions.
    // Both owner passes read the selected root and event payload.
    for _ in 0..2 {
        reader.reserve_owner_read(event_root_bytes.len())?;
        reader.reserve_owner_read(bytes.len())?;
    }
    let (event, receipt) = deployment.current_event_authority(event_id)?;
    if event != parsed || receipt.event_root != current.payload_digest {
        return Err(LongEventReplayError::AuthorityChanged);
    }
    if pins.is_some_and(|pins| pins.event_revision != event.revision_digest()) {
        return Err(LongEventReplayError::StaleSelection);
    }
    let identity = event_identity(event_id, if kind == "long_watch" { "event:long-watch:" } else { "event:long-corroborated:" })?;
    let provenance_root = published_root(deployment, &slot(prefix, identity)?)?;
    if pins.is_some_and(|pins| pins.provenance_root != provenance_root) {
        return Err(LongEventReplayError::StaleSelection);
    }
    let loaded = if kind == "long_watch" {
        watch::load(deployment, &event, identity, provenance_root, limits, &mut reader, cx)?
    } else {
        corroboration::load(deployment, &event, identity, provenance_root, limits, &mut reader, cx)?
    };
    for source in &loaded.sources {
        verify_source_metadata(deployment, source, limits, &mut reader, cx)?;
    }
    unchanged(deployment, &basis, cx)?;
    Ok(LongEventReplayInspection {
        pins: LongEventReplayPins { event_revision: event.revision_digest(), provenance_root },
        event, event_root: receipt.event_root, recipe: loaded.recipe,
        analysis_roots: loaded.analysis_roots, analysis_digests: loaded.analysis_digests,
        basis, metadata_bytes: reader.used,
    })
}

/// Inspect current original event metadata and source capsules without executing perception.
pub fn inspect_long_event(
    deployment: &ReferenceDeployment, event: &EventId, limits: &LongEventReplayLimits, cx: &ReplayCx,
) -> Result<LongEventReplayInspection> {
    load(deployment, event, None, limits, cx)
}

/// Execute the exact retained recipe under explicit ceilings and compare complete analyses/events.
/// Source bytes come from retained imports. No loose input, report, model file or remembered
/// command is required. Success is a read result, never a new authority/effect publication.
pub fn replay_long_event(
    deployment: &ReferenceDeployment, event: &EventId, pins: LongEventReplayPins,
    limits: &LongEventReplayLimits, cx: &ReplayCx,
) -> Result<VerifiedLongEventReplay> {
    let inspection = load(deployment, event, Some(pins), limits, cx)?;
    checkpoint(cx, "long_event_replay:execute")?;
    let (frames, source_bytes) = match &inspection.recipe {
        LongEventReplayRecipe::Watch(recipe) => {
            let actual = if recipe.screened() {
                LongWatchReport::analyze_screened(deployment, recipe.plan(), recipe.options(), recipe.limits(), cx)?
            } else {
                LongWatchReport::analyze(deployment, recipe.plan(), recipe.options(), recipe.limits(), cx)?
            };
            if actual.publication_blocked()
                || inspection.analysis_digests != [actual.analysis_digest()]
                || inspection.analysis_roots != [actual.replay_analysis_root()] {
                return Err(LongEventReplayError::Diverged);
            }
            let candidate = actual.candidates().iter().find(|candidate| candidate.event().event_id == *event)
                .ok_or(LongEventReplayError::Diverged)?;
            if candidate.status() != WatchStatus::AlreadyPublished || candidate.event() != inspection.event()
                || candidate.event().decision_path.fingerprint != pins.provenance_root {
                return Err(LongEventReplayError::Diverged);
            }
            (actual.frames_decoded(), actual.source_chunk_bytes_read())
        }
        LongEventReplayRecipe::Corroboration(recipe) => {
            let actual = recipe.analyze(deployment, cx)?;
            if actual.publication_blocked() {
                return Err(LongEventReplayError::Diverged);
            }
            let cameras: Vec<_> = actual.replay_camera_summaries().collect();
            if cameras.len() != 2
                || cameras.iter().map(|camera| camera.0).collect::<Vec<_>>() != inspection.analysis_roots
                || cameras.iter().map(|camera| camera.1).collect::<Vec<_>>() != inspection.analysis_digests {
                return Err(LongEventReplayError::Diverged);
            }
            let candidate = actual.candidates().iter().find(|candidate| candidate.event().event_id == *event)
                .ok_or(LongEventReplayError::Diverged)?;
            if candidate.status() != CorroborationStatus::AlreadyPublished || candidate.event() != inspection.event()
                || candidate.provenance_root() != pins.provenance_root {
                return Err(LongEventReplayError::Diverged);
            }
            let frames = cameras.iter().try_fold(0_usize, |sum, camera| sum.checked_add(camera.2))
                .ok_or(LongEventReplayError::Limit)?;
            let bytes = cameras.iter().try_fold(0_u64, |sum, camera| sum.checked_add(camera.3))
                .ok_or(LongEventReplayError::Limit)?;
            (frames, bytes)
        }
    };
    unchanged(deployment, &inspection.basis, cx)?;
    checkpoint(cx, "long_event_replay:complete")?;
    Ok(VerifiedLongEventReplay { inspection, frames, source_bytes })
}

#[cfg(test)]
mod tests;
