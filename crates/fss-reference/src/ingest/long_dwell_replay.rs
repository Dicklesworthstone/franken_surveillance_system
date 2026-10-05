#![forbid(unsafe_code)]
//! Cold, source-backed replay of committed whole-recording dwell events.
//!
//! Inspection proves selected custody and decodes the original recipe; it does not validate
//! perception. Verification runs the real decoder, current privacy projection, foreground,
//! tracker, dwell and optional health screen, then compares the entire canonical trace and event.
//! Nothing is staged, published, repaired, sent or marked verified in persistent authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use fss_core::{ContentDigest, ContractError, DigestAlgorithm, EventHypothesis, EventId, EventKind,
    EventState, EvidenceClass, EvidenceEdgeRelation, LedgerAnchor, ObjectId};
use fss_object::{HostSpoolIo, ObjectManifest, read_verified_payload};
use fss_publication::{ROOT_REACHABILITY_FAMILY, SlotName};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};
use super::long_dwell::{LongDwellLimits, LongDwellReport, MAX_LONG_DWELL_FRAMES, MAX_LONG_DWELL_TRACE_BYTES};
use super::privacy_mask::current_mask;
use super::recorded_decode::{RecordedDecodeError, source_capsule};
use super::recorded_watch::{WatchError, WatchStatus};
use super::sensor_health::{policy_bytes as health_policy_bytes, policy_digest as health_policy_digest};
use super::{FileIngestError, RetainedFileImport};

mod recipe;
pub use recipe::DwellReplayRecipe;
use recipe::{ANALYSIS_DOMAIN, POLICY, episode_analysis};

/// Existing trace ceiling plus bounded recipe and optional health metadata.
pub const MAX_ANALYSIS_BYTES: usize = MAX_LONG_DWELL_TRACE_BYTES + 32 * 1024;
/// Hard cumulative selected-metadata read ceiling, excluding deployment open and source replay.
pub const MAX_REPLAY_METADATA_BYTES: usize = 32 * 1024 * 1024;
const MAX_METADATA_OBJECTS: usize = 16;
const ANALYSIS_KIND: &str = "recorded-long-dwell-analysis-v1";
const EPISODE_KIND: &str = "recorded-long-dwell-episode-v1";

type Result<T> = std::result::Result<T, DwellReplayError>;

/// Explicit bounds. Native execution retains its existing whole-scan, never-refilled budgets.
#[derive(Clone, Copy, Debug)]
pub struct DwellReplayLimits {
    /// Source reads, codec, pixel, assignment and trace ceilings for the actual replay.
    pub execution: LongDwellLimits,
    /// Aggregate selected metadata payloads read by this adapter; not total-system I/O.
    pub maximum_metadata_bytes: usize,
}
impl Default for DwellReplayLimits {
    fn default() -> Self {
        Self { execution: LongDwellLimits::default(), maximum_metadata_bytes: 16 * 1024 * 1024 }
    }
}
impl DwellReplayLimits {
    /// Validate before reading metadata or executing perception.
    pub fn validate(&self) -> Result<()> {
        self.execution.validate()?;
        if !(1..=MAX_REPLAY_METADATA_BYTES).contains(&self.maximum_metadata_bytes) {
            return Err(DwellReplayError::Limit);
        }
        Ok(())
    }
}

/// Exact selected event revision and shared analysis root, supplied before native execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DwellReplayPins {
    /// Canonical event revision, not an approval or an event identifier alone.
    pub event_revision: ContentDigest,
    /// Complete shared analysis graph, including its source, recipe and optional screening.
    pub analysis_root: ContentDigest,
}

/// A refusal never returns a partial or successful verification result.
#[derive(Debug)]
pub enum DwellReplayError {
    /// Selected metadata violates its existing closed encoding or cross-record bindings.
    InvalidRecord,
    /// This is not a supported v1 whole-recording dwell event/recipe.
    UnsupportedProfile,
    /// Caller pins do not name the currently committed event and analysis.
    StaleSelection,
    /// Current privacy no longer admits the original analysis lineage.
    PrivacyChanged,
    /// The durable authority head, root visibility or current root claim is not coherent.
    AuthorityChanged,
    /// Actual native replay differs from the retained trace, episode or event.
    Diverged,
    /// Input, metadata or work ceiling was exceeded.
    Limit,
    /// Cooperative cancellation; no verification is returned.
    Cancelled,
    /// Existing custody, native execution or deployment owner refused the operation.
    Source(Box<WatchError>),
}
impl DwellReplayError {
    /// Narrow machine-readable reason; none of these reasons certifies absence or health.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRecord => "invalid_dwell_replay_record",
            Self::UnsupportedProfile => "unsupported_dwell_replay_profile",
            Self::StaleSelection => "dwell_replay_selection_changed",
            Self::PrivacyChanged => "dwell_replay_privacy_changed",
            Self::AuthorityChanged => "dwell_replay_authority_changed",
            Self::Diverged => "dwell_native_replay_diverged",
            Self::Limit => "dwell_replay_bound_exceeded",
            Self::Cancelled => "dwell_replay_cancelled",
            Self::Source(_) => "dwell_replay_owner_refusal",
        }
    }
    /// Reuse the existing watch/decode families; the reason retains the replay distinction.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Limit => "ERR-WATCH-LIMIT-001",
            Self::Source(error) => error.stable_id(),
            _ => "ERR-WATCH-001",
        }
    }
}
impl fmt::Display for DwellReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stable_id(), self.reason())?;
        if let Self::Source(error) = self { write!(f, ": {error}")?; }
        Ok(())
    }
}
impl std::error::Error for DwellReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { Self::Source(error) => Some(error.as_ref()), _ => None }
    }
}
impl From<ContractError> for DwellReplayError {
    fn from(_: ContractError) -> Self { Self::InvalidRecord }
}
impl From<WatchError> for DwellReplayError {
    fn from(error: WatchError) -> Self { Self::Source(Box::new(error)) }
}
impl From<ReferenceError> for DwellReplayError {
    fn from(error: ReferenceError) -> Self { WatchError::from(error).into() }
}
impl From<FileIngestError> for DwellReplayError {
    fn from(error: FileIngestError) -> Self { WatchError::from(error).into() }
}
impl From<RecordedDecodeError> for DwellReplayError {
    fn from(error: RecordedDecodeError) -> Self { WatchError::from(error).into() }
}
impl From<fss_object::SpoolError> for DwellReplayError {
    fn from(error: fss_object::SpoolError) -> Self { WatchError::from(error).into() }
}

pub(super) fn valid_digest(value: ContentDigest) -> Result<()> {
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err(DwellReplayError::InvalidRecord);
    }
    Ok(())
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage).map_err(|_| DwellReplayError::Cancelled)
}
fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn check_context(deployment: &ReferenceDeployment, cx: &ReplayCx) -> Result<()> {
    checkpoint(cx, "long_dwell_replay:read")?;
    if cx.root_dir() != deployment.root() || !cx.io_authority().is_valid() {
        return Err(DwellReplayError::AuthorityChanged);
    }
    deployment.ledger().verify_durable_head().map_err(|_| DwellReplayError::AuthorityChanged)
}

struct MetadataReader { remaining: usize, used: usize, objects: usize }
impl MetadataReader {
    fn read(&mut self, deployment: &ReferenceDeployment, digest: ContentDigest, maximum: usize, cx: &ReplayCx) -> Result<Vec<u8>> {
        checkpoint(cx, "long_dwell_replay:metadata")?;
        valid_digest(digest)?;
        if self.objects == MAX_METADATA_OBJECTS || self.remaining == 0 { return Err(DwellReplayError::Limit); }
        // Existing read-only spool owner caps allocation before reading and rejects symlinks.
        // The deployment lock and the active, root-scoped ReplayCx remain held throughout.
        let bytes = read_verified_payload(deployment.publisher().spool().root(), digest,
            maximum.min(self.remaining), &HostSpoolIo)?;
        self.objects += 1;
        self.remaining = self.remaining.checked_sub(bytes.len()).ok_or(DwellReplayError::Limit)?;
        self.used = self.used.checked_add(bytes.len()).ok_or(DwellReplayError::Limit)?;
        checkpoint(cx, "long_dwell_replay:metadata_read")?;
        Ok(bytes)
    }
}

/// Custody-backed metadata only. This type is deliberately distinct from VerifiedDwellReplay.
#[derive(Debug)]
pub struct DwellReplayInspection {
    event: EventHypothesis,
    event_root: ContentDigest,
    analysis_digest: ContentDigest,
    pins: DwellReplayPins,
    recipe: DwellReplayRecipe,
    basis: LedgerAnchor,
    metadata_bytes: usize,
}
impl DwellReplayInspection {
    /// Current event decoded through the guarded authority reader; not replay-certified yet.
    pub fn event(&self) -> &EventHypothesis { &self.event }
    /// Root of the currently published event revision.
    pub const fn event_root(&self) -> ContentDigest { self.event_root }
    /// Complete canonical analysis payload; reconstructed root is in `pins()`.
    pub const fn analysis_digest(&self) -> ContentDigest { self.analysis_digest }
    /// Exact current selection required by the native replay entry point.
    pub const fn pins(&self) -> DwellReplayPins { self.pins }
    /// Parameters reconstructed from retained canonical bytes, not command-line overrides.
    pub fn recipe(&self) -> &DwellReplayRecipe { &self.recipe }
    /// Authority snapshot this inspection consumed.
    pub fn basis(&self) -> &LedgerAnchor { &self.basis }
    /// Selected metadata payload bytes re-read by this adapter (not source replay or open cost).
    pub const fn metadata_bytes_read(&self) -> usize { self.metadata_bytes }
}

/// Constructible only after actual native execution matches the complete trace and event.
#[derive(Debug)]
pub struct VerifiedDwellReplay {
    inspection: DwellReplayInspection,
    frames: usize,
    source_bytes: u64,
}
impl VerifiedDwellReplay {
    /// Exact selected custody and original recipe that the native execution reproduced.
    pub fn inspection(&self) -> &DwellReplayInspection { &self.inspection }
    /// Frames actually decoded by replay; refused source positions are not counted as frames.
    pub const fn frames_replayed(&self) -> usize { self.frames }
    /// Verified source-chunk bytes fetched by the real forward cursor.
    pub const fn source_chunk_bytes_read(&self) -> u64 { self.source_bytes }
}

struct Loaded { inspection: DwellReplayInspection, analysis: Vec<u8> }
fn published_root(deployment: &ReferenceDeployment, prefix: &str, identity: ContentDigest, root: ContentDigest) -> Result<()> {
    let slot = SlotName::parse(&format!("{prefix}-{}", hex(identity))).map_err(|_| DwellReplayError::InvalidRecord)?;
    let object = ObjectId::parse(format!("object:local-root:{}", slot.as_str()))?;
    let current = deployment.ledger().current().objects.get(&object).ok_or(DwellReplayError::AuthorityChanged)?;
    if current.family != ROOT_REACHABILITY_FAMILY || current.generation != 1 || current.payload_digest != root
        || deployment.publisher().root(&slot).is_none_or(|visible| visible.root != root)
    { return Err(DwellReplayError::AuthorityChanged); }
    Ok(())
}
fn manifest(bytes: &[u8], kind: &str, maximum: usize) -> Result<ObjectManifest> {
    let value = ObjectManifest::from_canonical_bytes(bytes).map_err(|_| DwellReplayError::InvalidRecord)?;
    if value.kind() != kind || value.metadata_digest().is_some() || value.children().len() > maximum {
        return Err(DwellReplayError::InvalidRecord);
    }
    Ok(value)
}

fn load(deployment: &ReferenceDeployment, event_id: &EventId, pins: Option<DwellReplayPins>, limits: &DwellReplayLimits, cx: &ReplayCx) -> Result<Loaded> {
    limits.validate()?;
    check_context(deployment, cx)?;
    let basis = deployment.current_anchor().clone();
    if let Some(pins) = pins { valid_digest(pins.event_revision)?; valid_digest(pins.analysis_root)?; }
    let (event, receipt) = deployment.current_event_authority(event_id)?;
    if pins.is_some_and(|pins| pins.event_revision != event.revision_digest()) { return Err(DwellReplayError::StaleSelection); }
    if event.revision != 1 || event.supersedes.is_some() || event.kind != EventKind::Unclassified
        || event.state != EventState::Indeterminate || !event.decision_path.abstained
        || event.decision_path.policy_generation != ContentDigest::sha256(POLICY)
    { return Err(DwellReplayError::UnsupportedProfile); }
    let suffix = event.event_id.as_str().strip_prefix("event:long-dwell:").ok_or(DwellReplayError::UnsupportedProfile)?;
    if suffix.len() != 64 || !suffix.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err(DwellReplayError::InvalidRecord); }
    let record_digest = ContentDigest::parse(&format!("sha256:{suffix}"))?;
    if !event.evidence.iter().any(|item| item.digest == record_digest && item.class == EvidenceClass::Derived
        && item.relation == EvidenceEdgeRelation::DerivedFrom && !item.supports)
    { return Err(DwellReplayError::InvalidRecord); }
    let mut reader = MetadataReader { remaining: limits.maximum_metadata_bytes, used: 0, objects: 0 };
    let record = reader.read(deployment, record_digest, 2048, cx)?;
    let analysis_root = episode_analysis(&record)?;
    if pins.is_some_and(|pins| pins.analysis_root != analysis_root) { return Err(DwellReplayError::StaleSelection); }
    let episode_root = event.decision_path.fingerprint;
    let episode = manifest(&reader.read(deployment, episode_root, 4096, cx)?, EPISODE_KIND, 2)?;
    if episode.children().len() != 2 || !episode.children().contains(&record_digest) || !episode.children().contains(&analysis_root) {
        return Err(DwellReplayError::InvalidRecord);
    }
    published_root(deployment, "ld-e", record_digest, episode_root)?;
    let shared = manifest(&reader.read(deployment, analysis_root, 4096, cx)?, ANALYSIS_KIND, 6)?;
    let mut objects = BTreeMap::new();
    let mut selected = None;
    for &child in shared.children() {
        let bytes = reader.read(deployment, child, MAX_ANALYSIS_BYTES, cx)?;
        let mut header = fss_core::CanonicalDecoder::new(&bytes);
        if header.text().ok() == Some(ANALYSIS_DOMAIN) {
            if selected.replace(child).is_some() { return Err(DwellReplayError::InvalidRecord); }
        }
        objects.insert(child, bytes);
    }
    let analysis_digest = selected.ok_or(DwellReplayError::InvalidRecord)?;
    published_root(deployment, "ld-a", analysis_digest, analysis_root)?;
    let analysis = objects.remove(&analysis_digest).ok_or(DwellReplayError::InvalidRecord)?;
    let recipe = DwellReplayRecipe::decode(&analysis, &mut || checkpoint(cx, "long_dwell_replay:record"))?;
    if recipe.site != deployment.site_lineage() { return Err(DwellReplayError::InvalidRecord); }
    let sensor_digest = ContentDigest::sha256(recipe.sensor.as_str().as_bytes());
    if objects.get(&sensor_digest).map(Vec::as_slice) != Some(recipe.sensor.as_str().as_bytes())
        || objects.get(&ContentDigest::sha256(POLICY)).map(Vec::as_slice) != Some(POLICY)
    { return Err(DwellReplayError::InvalidRecord); }
    // No old mask or no-policy fallback may be replayed under current stricter privacy.
    let privacy = current_mask(deployment, &recipe.sensor).map_err(RecordedDecodeError::from)?;
    if privacy.digest() != recipe.privacy { return Err(DwellReplayError::PrivacyChanged); }
    let mut expected = BTreeSet::from([recipe.import_root, analysis_digest, sensor_digest, ContentDigest::sha256(POLICY)]);
    if let Some(policy) = privacy.policy() {
        if objects.get(&policy.digest()).map(Vec::as_slice) != Some(policy.to_bytes().as_slice()) { return Err(DwellReplayError::InvalidRecord); }
        expected.insert(policy.digest());
    }
    if recipe.screened {
        if objects.get(&health_policy_digest()).map(Vec::as_slice) != Some(health_policy_bytes()) { return Err(DwellReplayError::InvalidRecord); }
        expected.insert(health_policy_digest());
    }
    if shared.children().iter().copied().collect::<BTreeSet<_>>() != expected { return Err(DwellReplayError::InvalidRecord); }
    let retained = RetainedFileImport::open(deployment, recipe.plan.import_identity, limits.execution.decode.read_limits, cx)?;
    if retained.import_root() != recipe.import_root || retained.manifest_digest() != recipe.manifest
        || retained.authority_anchor() != &recipe.source_anchor || retained.manifest().format != "mjpeg"
        || retained.manifest().capture_time_label != "operator_assumption"
    { return Err(DwellReplayError::InvalidRecord); }
    let (capsule, _) = source_capsule(deployment, &retained, recipe.plan.first_segment)?;
    if capsule.sensor_id != recipe.sensor { return Err(DwellReplayError::InvalidRecord); }
    check_context(deployment, cx)?;
    if deployment.current_anchor() != &basis { return Err(DwellReplayError::AuthorityChanged); }
    Ok(Loaded { analysis, inspection: DwellReplayInspection {
        pins: DwellReplayPins { event_revision: event.revision_digest(), analysis_root },
        event, event_root: receipt.event_root, analysis_digest, recipe, basis, metadata_bytes: reader.used,
    } })
}

/// Inspect a currently committed event and reconstruct its stored recipe without decoding media.
/// A preview-only or merely staged event cannot enter this path. Inspection is NOT native replay.
pub fn inspect_dwell(deployment: &ReferenceDeployment, event: &EventId, limits: &DwellReplayLimits, cx: &ReplayCx) -> Result<DwellReplayInspection> {
    Ok(load(deployment, event, None, limits, cx)?.inspection)
}

/// Reconstruct and execute the exact retained recipe, requiring a separately supplied selection.
/// Execution reads retained source, not an input path or caller-supplied trace. It never calls
/// any publisher, modifies the effect journal, or upgrades an event's epistemic state.
pub fn replay_dwell(deployment: &ReferenceDeployment, event: &EventId, pins: DwellReplayPins, limits: &DwellReplayLimits, cx: &ReplayCx) -> Result<VerifiedDwellReplay> {
    let Loaded { inspection, analysis } = load(deployment, event, Some(pins), limits, cx)?;
    checkpoint(cx, "long_dwell_replay:execute")?;
    let recipe = &inspection.recipe;
    let run = if recipe.screened { LongDwellReport::analyze_screened } else { LongDwellReport::analyze };
    let actual = run(deployment, &recipe.plan, recipe.rule, recipe.options, &limits.execution, cx)?;
    if actual.analysis_digest() != ContentDigest::sha256(&analysis) || actual.publication_blocked() {
        return Err(DwellReplayError::Diverged);
    }
    let candidate = actual.candidates().iter().find(|candidate| candidate.event().event_id == *event).ok_or(DwellReplayError::Diverged)?;
    if candidate.status() != WatchStatus::AlreadyPublished || candidate.event().revision_digest() != pins.event_revision {
        return Err(DwellReplayError::Diverged);
    }
    check_context(deployment, cx)?;
    if deployment.current_anchor() != &inspection.basis { return Err(DwellReplayError::AuthorityChanged); }
    checkpoint(cx, "long_dwell_replay:complete")?;
    Ok(VerifiedDwellReplay { frames: actual.frames_decoded(), source_bytes: actual.source_chunk_bytes_read(), inspection })
}

#[cfg(test)]
mod tests;
