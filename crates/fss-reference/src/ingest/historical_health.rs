#![forbid(unsafe_code)]
//! Independently retained, source-closed historical visual-health diagnostics.
//!
//! A diagnostic says what conservative screening of a finite, privacy-masked recording
//! reported. It never establishes current health, an outage, tampering, continuous coverage,
//! absence, or a later restoration. Every exact receipt remains independently addressable.
//! Its native scan and limits are the existing long-watch/dwell owners. Event approval and
//! the event publication health gate are deliberately unchanged.

use std::collections::BTreeSet;
use std::fmt;

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, ContractError,
    DigestAlgorithm, EvidenceDelta, EvidenceDeltaBatch, LedgerAnchor, ObjectId, Plane,
    SensorCapsule, SensorId, StreamId,
};
use fss_object::ObjectManifest;
use fss_publication::ROOT_REACHABILITY_FAMILY;

use super::long_dwell::{
    LongDwellHealthSummary, LongDwellLimits, MAX_LONG_DWELL_FRAMES, MAX_LONG_DWELL_TRACE_BYTES,
    ScanRule, json, publish_manifest, run_scan, slot,
};
use super::privacy_mask::{MaskBinding, PrivacyMaskPolicy, binding_digest, current_mask};
use super::recorded_decode::RecordedDecodeError;
use super::recorded_watch::{SourcePublicationGuard, WatchError, WatchOptions, WatchPlan};
use super::sensor_health::{policy_bytes, policy_digest};
use super::{FileIngestError, RetainedFileImport};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

mod wire;

/// Guarded authority family for literal retained historical screening reports.
pub const FAMILY_HISTORICAL_HEALTH: &str = "historical_sensor_health";
/// Generic ledger append may not create or shadow this namespace under any family.
pub const HISTORICAL_HEALTH_OBJECT_PREFIX: &str = "object:historical-sensor-health:";
/// Canonical bounded receipt profile, including the complete native replay recipe.
pub const HISTORICAL_HEALTH_RECORD_DOMAIN: &str = "fss.historical_sensor_health_record.v1";
/// Independent exact retention approval; it cannot approve an event.
pub const HISTORICAL_HEALTH_APPROVAL_DOMAIN: &str = "fss.historical_sensor_health_approval.v1";
/// The small receipt never embeds source media, pixels or the full native trace.
pub const MAX_HISTORICAL_HEALTH_RECORD_BYTES: usize = 64 * 1024;
/// Cumulative selected metadata ceiling for cold inspection and explicit replay.
pub const MAX_HISTORICAL_HEALTH_METADATA_BYTES: usize = 256 * 1024 * 1024;
const MANIFEST_KIND: &str = "historical-sensor-health-v1";
const MAX_ROOT_BYTES: usize = 4096;
const POLICY: &[u8] = b"fss.historical-sensor-health.v1:finite-masked-native-scan:operator-capture-hints:sample-hull-not-continuous-coverage:exact-source-privacy-recipe-and-trace:independent-retention-approval:append-only-per-receipt:no-current-health:no-outage:no-tamper:no-absence:no-alert";
type Result<T> = std::result::Result<T, HistoricalHealthError>;

/// Current caller admission is independent of every reservation in the historical recipe.
#[derive(Clone, Copy, Debug)]
pub struct HistoricalHealthReadLimits {
    /// Cumulative receipt, manifest, policy, deletion-plan and selected trace payload bytes.
    /// Existing import opening, privacy-owner lookup, source custody verification and native
    /// scanning retain their own bounded source/codec owners and do not spend this allowance.
    pub maximum_metadata_bytes: usize,
    /// Each original read/codec/whole-scan reservation must fit before native execution.
    pub execution: LongDwellLimits,
}
impl Default for HistoricalHealthReadLimits {
    fn default() -> Self {
        Self {
            maximum_metadata_bytes: 64 * 1024 * 1024,
            execution: LongDwellLimits::default(),
        }
    }
}
impl HistoricalHealthReadLimits {
    /// Validate before any selected metadata is read or replay is admitted.
    pub fn validate(&self) -> Result<()> {
        self.execution.validate()?;
        if !(1..=MAX_HISTORICAL_HEALTH_METADATA_BYTES).contains(&self.maximum_metadata_bytes) {
            return Err(HistoricalHealthError::Limit);
        }
        Ok(())
    }
}

/// Explicit refusal; no error constitutes a health finding or a successful native verification.
#[derive(Debug)]
pub enum HistoricalHealthError {
    /// Selected receipt, policy, root or committed cross-record binding is malformed.
    InvalidRecord,
    /// Exact selected content was not committed or is unavailable/deleted.
    Unavailable,
    /// The approval belongs to a different diagnostic or principal.
    ApprovalMismatch,
    /// Current privacy differs from the native scan; historical metadata remains historical.
    PrivacyChanged,
    /// Deployment authority or an independently pinned provenance root changed.
    AuthorityChanged,
    /// Original native execution did not reproduce the exact receipt and complete trace.
    Diverged,
    /// A cumulative read or original execution reservation exceeds its current ceiling.
    Limit,
    /// Cooperative cancellation; a completed durable prefix may remain retryable.
    Cancelled,
    /// The existing source, decoder, privacy or publication owner refused.
    Source(Box<WatchError>),
}
impl HistoricalHealthError {
    /// Stable diagnostic reason within the existing watch error family.
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidRecord => "invalid_historical_health_record",
            Self::Unavailable => "historical_health_unavailable",
            Self::ApprovalMismatch => "historical_health_approval_mismatch",
            Self::PrivacyChanged => "historical_health_privacy_changed",
            Self::AuthorityChanged => "historical_health_authority_changed",
            Self::Diverged => "historical_health_native_replay_diverged",
            Self::Limit => "historical_health_bound_exceeded",
            Self::Cancelled => "historical_health_cancelled",
            Self::Source(_) => "historical_health_owner_refusal",
        }
    }
    /// Existing registered watch error family; `reason` carries the diagnostic refinement.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Limit => "ERR-WATCH-LIMIT-001",
            Self::ApprovalMismatch => "ERR-WATCH-APPROVAL-STALE-001",
            Self::Source(error) => error.stable_id(),
            _ => "ERR-WATCH-001",
        }
    }
}
impl fmt::Display for HistoricalHealthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.stable_id(), self.reason())?;
        if let Self::Source(error) = self {
            write!(f, ": {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for HistoricalHealthError {}
impl From<ContractError> for HistoricalHealthError {
    fn from(_: ContractError) -> Self {
        Self::InvalidRecord
    }
}
impl From<WatchError> for HistoricalHealthError {
    fn from(error: WatchError) -> Self {
        if matches!(error, WatchError::Limit) {
            Self::Limit
        } else {
            Self::Source(Box::new(error))
        }
    }
}
macro_rules! owner_error {
    ($source:ty) => {
        impl From<$source> for HistoricalHealthError {
            fn from(error: $source) -> Self {
                WatchError::from(error).into()
            }
        }
    };
}
owner_error!(ReferenceError);
owner_error!(RecordedDecodeError);
owner_error!(FileIngestError);
owner_error!(fss_object::ObjectError);
owner_error!(fss_object::SpoolError);
owner_error!(fss_publication::LocalPublicationError);
impl From<crate::deletion::DeletionError> for HistoricalHealthError {
    fn from(_: crate::deletion::DeletionError) -> Self {
        Self::Unavailable
    }
}

/// Compact historical header. Finding endpoint measurements resolve in the separately retained
/// complete masked-scan trace. Decoding the header never proves native execution or live health.
#[derive(Clone, Debug)]
pub struct HistoricalHealthRecord {
    site: String,
    plan: WatchPlan,
    rule: ScanRule,
    options: WatchOptions,
    limits: LongDwellLimits,
    import_root: ContentDigest,
    manifest_digest: ContentDigest,
    source_anchor: LedgerAnchor,
    sensor: SensorId,
    stream: StreamId,
    media_format: String,
    capture_scope: CaptureInterval,
    privacy_policy: Option<ContentDigest>,
    privacy_generation: Option<u64>,
    summary: LongDwellHealthSummary,
    trace_digest: ContentDigest,
    trace_bytes: usize,
    unreliable: usize,
    restarts: usize,
    source_bytes: u64,
    pixel_samples: u64,
    assignment_work: u64,
    jpeg_work: u64,
}
impl HistoricalHealthRecord {
    /// Exact bounded canonical header bytes; no content digest relies on JSON spelling.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire::encode(self)
    }
    /// Decode one complete canonical v1 record with every count checked before allocation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        wire::decode(bytes)
    }
    /// Exact receipt payload identity.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.to_bytes())
    }
    /// Exact receipt payload identity, convenient for cold inspection clients.
    pub fn record_digest(&self) -> ContentDigest {
        self.digest()
    }
    /// Source import identity used by the canonical import and deletion owners.
    pub const fn import_identity(&self) -> ContentDigest {
        self.plan.import_identity
    }
    /// Root-last source custody root, not an event or a live sensor identity.
    pub const fn import_root(&self) -> ContentDigest {
        self.import_root
    }
    /// Canonical source manifest payload identity.
    pub const fn manifest_digest(&self) -> ContentDigest {
        self.manifest_digest
    }
    /// Site of the committed import and historical diagnostic.
    pub fn site_lineage(&self) -> &str {
        &self.site
    }
    /// Sensor bound by all screened source capsules.
    pub const fn sensor_id(&self) -> &SensorId {
        &self.sensor
    }
    /// Stream bound by all screened source capsules.
    pub const fn stream_id(&self) -> &StreamId {
        &self.stream
    }
    /// Requested first coding segment, distinct from an inferred outage start.
    pub const fn first_segment(&self) -> usize {
        self.plan.first_segment
    }
    /// Requested source positions, including explicitly refused/unscreened positions.
    pub const fn segment_count(&self) -> usize {
        self.plan.segment_count
    }
    /// Historical capsule-hint hull; `capture_scope_semantics` distinguishes screened samples
    /// from requested-source hints when no frame could be decoded. Gaps inside are not filled.
    pub const fn capture_scope(&self) -> CaptureInterval {
        self.capture_scope
    }
    /// Exact scope interpretation, including the entirely refused diagnostic case.
    pub fn capture_scope_semantics(&self) -> &'static str {
        if self.summary.frames_screened() == 0 {
            "requested_source_capsule_hints_when_no_frames_screened"
        } else {
            "hull_of_screened_capsule_hints_not_continuous_coverage"
        }
    }
    /// File-import timing remains explicitly an operator assumption.
    pub const fn capture_time_label(&self) -> &'static str {
        "operator_assumption"
    }
    /// Whether decoded sample timing remained admitted; this does not upgrade clock provenance.
    pub const fn time_reliable(&self) -> bool {
        self.summary.frames_screened() != 0 && self.unreliable == 0
    }
    /// Historical mask/no-policy binding, never silently replaced by the current one.
    pub fn privacy_digest(&self) -> ContentDigest {
        binding_digest(self.privacy_policy)
    }
    /// Exact historical privacy generation, or the explicit no-policy marker.
    pub const fn privacy_generation(&self) -> Option<u64> {
        self.privacy_generation
    }
    /// Optional retained historical mask policy payload.
    pub const fn privacy_policy_digest(&self) -> Option<ContentDigest> {
        self.privacy_policy
    }
    /// `suspected_degradation`, `incomplete` or `no_findings`; never a health certificate.
    pub fn status(&self) -> &'static str {
        self.summary.status()
    }
    /// Exact finite-range screening summary.
    pub const fn summary(&self) -> &LongDwellHealthSummary {
        &self.summary
    }
    /// Complete canonical masked native trace, held outside the compact header.
    pub const fn trace_digest(&self) -> ContentDigest {
        self.trace_digest
    }
    /// Exact bounded trace allocation required by native verification.
    pub const fn trace_bytes(&self) -> usize {
        self.trace_bytes
    }
    /// Source import completion anchor; independent of later diagnostic publication.
    pub const fn source_anchor(&self) -> &LedgerAnchor {
        &self.source_anchor
    }
    /// Original native source/codec/aggregate execution reservations.
    pub const fn execution_limits(&self) -> &LongDwellLimits {
        &self.limits
    }
    /// Literal finite-range metadata; every negative world claim remains explicitly false.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\"format\":{},\"record_digest\":{},\"site\":{},\"import_identity\":{},\"import_root\":{},",
                "\"manifest_digest\":{},\"sensor_id\":{},\"stream_id\":{},\"media_format\":{},",
                "\"first_segment\":{},\"segment_count\":{},\"capture_scope\":{{\"earliest_ns\":\"{}\",\"latest_ns\":\"{}\"}},",
                "\"capture_time_label\":\"operator_assumption\",\"capture_scope_semantics\":{},",
                "\"time_reliable\":{},\"privacy_binding\":{},\"privacy_generation\":{},\"status\":{},\"sensor_health\":{},",
                "\"trace_digest\":{},\"trace_bytes\":{},\"source_anchor_sequence\":{},\"source_anchor_root\":{},",
                "\"source_chunk_bytes_read\":{},\"pixel_samples_processed\":{},\"assignment_work_admitted\":{},\"jpeg_work_units\":{},",
                "\"unreliable_time_frames\":{},\"tracking_restarts\":{},\"historical_only\":true,\"current_health_proved\":false,",
                "\"outage_proved\":false,\"tamper_proved\":false,\"absence_certifiable\":false,\"alert_authorized\":false}}"
            ),
            json(HISTORICAL_HEALTH_RECORD_DOMAIN),
            json(&self.digest().to_text()),
            json(&self.site),
            json(&self.import_identity().to_text()),
            json(&self.import_root.to_text()),
            json(&self.manifest_digest.to_text()),
            json(self.sensor.as_str()),
            json(self.stream.as_str()),
            json(&self.media_format),
            self.first_segment(),
            self.segment_count(),
            self.capture_scope.earliest.0,
            self.capture_scope.latest.0,
            json(self.capture_scope_semantics()),
            self.time_reliable(),
            json(&self.privacy_digest().to_text()),
            self.privacy_generation
                .map_or("null".into(), |n| n.to_string()),
            json(self.status()),
            self.summary.to_json(),
            json(&self.trace_digest.to_text()),
            self.trace_bytes,
            self.source_anchor.commit_sequence,
            json(&self.source_anchor.state_root.to_text()),
            self.source_bytes,
            self.pixel_samples,
            self.assignment_work,
            self.jpeg_work,
            self.unreliable,
            self.restarts
        )
    }

    fn manifest(&self) -> Result<ObjectManifest> {
        let mut children = BTreeSet::from([self.trace_digest, self.import_root, policy_digest()]);
        if let Some(policy) = self.privacy_policy {
            children.insert(policy);
        }
        Ok(ObjectManifest::new(
            MANIFEST_KIND,
            children,
            Some(self.digest()),
        )?)
    }
    fn delta(&self, root: ContentDigest) -> Result<EvidenceDelta> {
        let identity = hex(self.digest());
        Ok(EvidenceDelta {
            delta_id: format!("delta:historical-health:{identity}"),
            family: FAMILY_HISTORICAL_HEALTH.into(),
            object_id: ObjectId::parse(format!("{HISTORICAL_HEALTH_OBJECT_PREFIX}{identity}"))?,
            prior_generation: None,
            new_generation: 1,
            validity: self.capture_scope,
            plane: Plane::Authority,
            payload_digest: self.digest(),
            witness_digest: Some(root),
            operation_id: None,
        })
    }
}

/// An immutable native scan plus independent retention authority. Construction is private to the
/// masked whole-recording scanner, so callers cannot publish a fabricated diagnostic header.
#[derive(Debug)]
pub struct HistoricalHealthDiagnostic {
    record: HistoricalHealthRecord,
    trace: Vec<u8>,
    privacy: MaskBinding,
    guard: SourcePublicationGuard,
    manifest: ObjectManifest,
    approval: ContentDigest,
    already_retained: bool,
}
impl HistoricalHealthDiagnostic {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_scan(
        deployment: &ReferenceDeployment,
        plan: &WatchPlan,
        rule: ScanRule,
        options: WatchOptions,
        limits: &LongDwellLimits,
        source: &RetainedFileImport,
        capsule: &SensorCapsule,
        privacy: &MaskBinding,
        guard: &SourcePublicationGuard,
        capture_scope: CaptureInterval,
        unreliable: usize,
        restarts: usize,
        source_bytes: u64,
        pixel_samples: u64,
        assignment_work: u64,
        jpeg_work: u64,
        summary: &LongDwellHealthSummary,
        trace: &[u8],
        cx: &ReplayCx,
    ) -> Result<Self> {
        let record = HistoricalHealthRecord {
            site: deployment.site_lineage().into(),
            plan: plan.clone(),
            rule,
            options,
            limits: *limits,
            import_root: source.import_root(),
            manifest_digest: source.manifest_digest(),
            source_anchor: source.authority_anchor().clone(),
            sensor: capsule.sensor_id.clone(),
            stream: capsule.stream_id.clone(),
            media_format: source.manifest().format.clone(),
            capture_scope,
            privacy_policy: privacy.policy_digest(),
            privacy_generation: privacy.generation(),
            summary: summary.clone(),
            trace_digest: ContentDigest::sha256(trace),
            trace_bytes: trace.len(),
            unreliable,
            restarts,
            source_bytes,
            pixel_samples,
            assignment_work,
            jpeg_work,
        };
        // One writer and one strict reader agree before anything becomes approvable.
        HistoricalHealthRecord::from_bytes(&record.to_bytes())?;
        let manifest = record.manifest()?;
        let mut e = CanonicalEncoder::new();
        e.text(HISTORICAL_HEALTH_APPROVAL_DOMAIN);
        e.text(cx.io_authority().principal());
        e.digest(record.digest());
        e.digest(manifest.root());
        let approval = ContentDigest::sha256(&e.finish());
        let already_retained =
            retained_batch(deployment.ledger().batches(), record.digest()).is_some();
        if already_retained {
            read_retained_at(
                deployment.ledger().batches(),
                record.digest(),
                |digest, bound| Ok(deployment.publisher().spool().read_bounded(digest, bound)?),
            )?;
        }
        Ok(Self {
            record,
            trace: trace.to_vec(),
            privacy: privacy.clone(),
            guard: guard.clone(),
            manifest,
            approval,
            already_retained,
        })
    }
    /// Exact bounded historical receipt.
    pub const fn record(&self) -> &HistoricalHealthRecord {
        &self.record
    }
    /// Exact diagnostic receipt identity.
    pub fn record_digest(&self) -> ContentDigest {
        self.record.digest()
    }
    /// Deterministic source-closed provenance root, available before retention.
    pub fn provenance_root(&self) -> ContentDigest {
        self.manifest.root()
    }
    /// Independent principal- and source-bound approval; event approvals do not match it.
    pub const fn approval_digest(&self) -> ContentDigest {
        self.approval
    }
    /// Retention observed during this read-only scan; retries revalidate before relying on it.
    pub const fn already_retained(&self) -> bool {
        self.already_retained
    }
    /// Compact approval proposal. `receipt.status` retains the separate screening classification.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"record_digest\":{},\"approval_digest\":{},\"provenance_root\":{},\"already_retained\":{},\"status\":{},\"receipt\":{}}}",
            json(&self.record_digest().to_text()),
            json(&self.approval.to_text()),
            json(&self.provenance_root().to_text()),
            self.already_retained,
            json(if self.already_retained {
                "already_retained"
            } else {
                "prepared"
            }),
            self.record.to_json()
        )
    }
    /// Retain the exact diagnostic even when there are findings or no event candidates.
    /// Source bytes, every selected capsule, current privacy, deployment and principal are
    /// revalidated before staging and on retries. This never publishes events or dispatches effects.
    pub fn retain(
        &self,
        deployment: &mut ReferenceDeployment,
        approval: ContentDigest,
        cx: &ReplayCx,
    ) -> Result<HistoricalHealthRetention> {
        checkpoint(cx, "historical_health:retain")?;
        if approval != self.approval {
            return Err(HistoricalHealthError::ApprovalMismatch);
        }
        checkpoint(cx, "historical_health:publication_revalidate")?;
        self.guard.revalidate(deployment, cx)?;
        if let Some(batch) = retained_batch(deployment.ledger().batches(), self.record_digest()) {
            let ledger_anchor = batch.new_anchor.clone();
            let inspected = read_retained(
                deployment,
                self.record_digest(),
                &HistoricalHealthReadLimits::default(),
                cx,
            )?;
            if inspected.provenance_root != self.provenance_root() {
                return Err(HistoricalHealthError::InvalidRecord);
            }
            // Do not heal damaged trace custody from the transient in-memory scan on a retry.
            let trace = deployment
                .publisher()
                .spool()
                .read_bounded(self.record.trace_digest, self.record.trace_bytes)?;
            if trace != self.trace {
                return Err(HistoricalHealthError::InvalidRecord);
            }
            return Ok(HistoricalHealthRetention {
                record_digest: self.record_digest(),
                provenance_root: self.provenance_root(),
                ledger_anchor,
                already_retained: true,
            });
        }
        checkpoint(cx, "historical_health:stage")?;
        let record_bytes = self.record.to_bytes();
        for bytes in [
            record_bytes.as_slice(),
            self.trace.as_slice(),
            policy_bytes(),
        ] {
            let digest = deployment.stage_payload(bytes)?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        if let Some(policy) = self.privacy.policy() {
            let digest = deployment.stage_payload(&policy.to_bytes())?;
            deployment.publisher_mut().verify_object(digest)?;
        }
        let target = slot("hh", self.record_digest())?;
        publish_manifest(
            deployment,
            &target,
            &self.manifest,
            self.record.capture_scope,
            cx,
        )?;
        checkpoint(cx, "historical_health:commit")?;
        // Root publication can leave a durable prefix after interruption. Revalidate again
        // immediately before diagnostic authority so that prefix never bypasses a changed
        // privacy generation, source deletion, capsule damage or original principal.
        self.guard.revalidate(deployment, cx)?;
        let ledger_anchor = deployment.append_historical_health_batch(
            batch_id(self.record_digest())?,
            vec![self.record.delta(self.provenance_root())?],
            batch_children(self.record_digest(), self.provenance_root()),
            cx,
        )?;
        Ok(HistoricalHealthRetention {
            record_digest: self.record_digest(),
            provenance_root: self.provenance_root(),
            ledger_anchor,
            already_retained: false,
        })
    }
}

/// Committed diagnostic authority; no effect was prepared or transmitted.
#[derive(Clone, Debug)]
pub struct HistoricalHealthRetention {
    /// Receipt payload identity.
    pub record_digest: ContentDigest,
    /// Exact committed source-closed provenance root.
    pub provenance_root: ContentDigest,
    /// Diagnostic authority commit, after the root reachability commit.
    pub ledger_anchor: LedgerAnchor,
    /// True for a fully revalidated idempotent retry.
    pub already_retained: bool,
}

/// Checked retained metadata; only `native_verified` indicates successful native reproduction.
#[derive(Clone, Debug)]
pub struct HistoricalHealthReadReport {
    /// Canonical historical receipt, not a current sensor state.
    pub record: HistoricalHealthRecord,
    /// Source-closed provenance manifest root.
    pub provenance_root: ContentDigest,
    /// Original diagnostic publication anchor in the supplied committed prefix.
    pub ledger_anchor: LedgerAnchor,
    /// True only after exact native recipe and trace reproduction.
    pub native_verified: bool,
    /// Actual successfully decoded frames in explicit replay; zero for metadata-only inspection.
    pub frames_replayed: usize,
    /// Actual native replay source-chunk reads; zero for metadata-only inspection.
    pub source_chunk_bytes_read: u64,
}
impl HistoricalHealthReadReport {
    /// Separate metadata-inspection and native-reproduction facts in every report.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"status\":{},\"native_verified\":{},\"record_digest\":{},\"provenance_root\":{},\"authority_sequence\":{},\"frames_replayed\":{},\"source_chunk_bytes_read\":{},\"record\":{}}}",
            json(if self.native_verified {
                "native_replay_matched"
            } else {
                "inspected_not_replayed"
            }),
            self.native_verified,
            json(&self.record.digest().to_text()),
            json(&self.provenance_root.to_text()),
            self.ledger_anchor.commit_sequence,
            self.frames_replayed,
            self.source_chunk_bytes_read,
            self.record.to_json()
        )
    }
}

fn hex(digest: ContentDigest) -> String {
    digest.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage)
        .map_err(|_| HistoricalHealthError::Cancelled)
}
fn batch_id(digest: ContentDigest) -> Result<BatchId> {
    Ok(BatchId::parse(format!(
        "batch:historical-health:{}",
        hex(digest)
    ))?)
}
fn batch_children(record: ContentDigest, root: ContentDigest) -> Vec<ContentDigest> {
    let mut values = vec![record, root];
    values.sort_unstable();
    values
}
fn retained_batch(
    batches: &[EvidenceDeltaBatch],
    digest: ContentDigest,
) -> Option<&EvidenceDeltaBatch> {
    batches.iter().find(|batch| {
        batch
            .deltas
            .iter()
            .any(|delta| delta.family == FAMILY_HISTORICAL_HEALTH && delta.payload_digest == digest)
    })
}
fn valid_digest(digest: ContentDigest) -> Result<()> {
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    Ok(())
}

/// Lock-free metadata projection from an already verified committed prefix. The callback must
/// enforce its own cumulative read budget and the current deletion policy, including when the
/// prefix is historical. At most four payload reads occur: receipt, provenance, screening policy
/// and optional historical privacy policy. No trace, source, decoder, recovery or lock is opened.
pub fn read_retained_at(
    batches: &[EvidenceDeltaBatch],
    record_digest: ContentDigest,
    mut read: impl FnMut(ContentDigest, usize) -> Result<Vec<u8>>,
) -> Result<HistoricalHealthReadReport> {
    valid_digest(record_digest)?;
    let batch = retained_batch(batches, record_digest).ok_or(HistoricalHealthError::Unavailable)?;
    let bytes = read(record_digest, MAX_HISTORICAL_HEALTH_RECORD_BYTES)?;
    if ContentDigest::sha256(&bytes) != record_digest {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let record = HistoricalHealthRecord::from_bytes(&bytes)?;
    let manifest = record.manifest()?;
    let root = manifest.root();
    if batch.batch_id != batch_id(record_digest)?
        || batch.deltas != [record.delta(root)?]
        || batch.children != batch_children(record_digest, root)
        || batch.batch_digest != batch.computed_digest()
        || !batch.is_canonically_ordered()
        || batch.new_anchor.site_lineage != record.site
        || batch.basis_anchor.site_lineage != record.site
    {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let source = batches
        .iter()
        .find(|candidate| candidate.new_anchor == record.source_anchor)
        .ok_or(HistoricalHealthError::InvalidRecord)?;
    if source.batch_id.as_str()
        != format!(
            "batch:file-import:{}:manifest",
            hex(record.import_identity())
        )
        || !source.deltas.iter().any(|delta| {
            delta.family == "file_import"
                && delta.payload_digest == record.manifest_digest
                && delta.object_id.as_str()
                    == format!("object:file-import:{}", hex(record.import_identity()))
                && delta.plane == Plane::Authority
                && delta.prior_generation == Some(1)
                && delta.new_generation == 2
                && delta.witness_digest == Some(record.import_root)
        })
        || !source.deltas.iter().any(|delta| {
            delta.family == "file_import_manifest"
                && delta.payload_digest == record.manifest_digest
                && delta.object_id.as_str()
                    == format!(
                        "object:file-import-manifest:{}",
                        hex(record.import_identity())
                    )
                && delta.plane == Plane::Authority
                && delta.prior_generation.is_none()
                && delta.new_generation == 1
                && delta.witness_digest == Some(record.import_root)
        })
        || !source.children.contains(&record.manifest_digest)
        || !source.children.contains(&record.import_root)
    {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let publication_slot = slot("hh", record_digest)?;
    let root_object = format!("object:local-root:{publication_slot}");
    let prefix_end = batches
        .iter()
        .position(|candidate| std::ptr::eq(candidate, batch))
        .ok_or(HistoricalHealthError::InvalidRecord)?;
    let prefix = &batches[..prefix_end];
    let root_delta = prefix
        .iter()
        .flat_map(|candidate| &candidate.deltas)
        .rev()
        .find(|delta| delta.object_id.as_str() == root_object)
        .ok_or(HistoricalHealthError::InvalidRecord)?;
    if root_delta.family != ROOT_REACHABILITY_FAMILY
        || root_delta.plane != Plane::Authority
        || root_delta.prior_generation.is_some()
        || root_delta.new_generation != 1
        || root_delta.payload_digest != root
        || root_delta.validity != record.capture_scope
        || root_delta.witness_digest.is_some()
        || root_delta.operation_id.is_some()
        || !prefix
            .iter()
            .any(|candidate| candidate.new_anchor == record.source_anchor)
    {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    let root_bytes = read(root, MAX_ROOT_BYTES)?;
    if root_bytes != manifest.canonical_bytes() {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    if read(policy_digest(), policy_bytes().len())? != policy_bytes() {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    wire::check_historical_privacy(&record, prefix, &mut read)?;
    Ok(HistoricalHealthReadReport {
        record,
        provenance_root: root,
        ledger_anchor: batch.new_anchor.clone(),
        native_verified: false,
        frames_replayed: 0,
        source_chunk_bytes_read: 0,
    })
}

struct Metadata<'a> {
    deployment: &'a ReferenceDeployment,
    remaining: usize,
    cx: &'a ReplayCx,
}
impl Metadata<'_> {
    fn read(&mut self, digest: ContentDigest, maximum: usize) -> Result<Vec<u8>> {
        checkpoint(self.cx, "historical_health:metadata")?;
        if self.remaining == 0 {
            return Err(HistoricalHealthError::Limit);
        }
        let bytes = self
            .deployment
            .publisher()
            .spool()
            .read_bounded(digest, maximum.min(self.remaining))?;
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or(HistoricalHealthError::Limit)?;
        Ok(bytes)
    }
}
fn inspect(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    reader: &mut Metadata<'_>,
) -> Result<HistoricalHealthReadReport> {
    let batches = deployment.ledger().batches();
    let deletions = crate::deletion::DeletionIndex::from_batches(batches, |digest| {
        reader.read(digest, crate::deletion::MAX_DELETION_RECORD_BYTES)
    })?;
    let report = read_retained_at(batches, digest, |digest, bound| {
        if deletions.object(digest).is_some() {
            return Err(HistoricalHealthError::Unavailable);
        }
        reader.read(digest, bound)
    })?;
    if report.record.site != deployment.site_lineage()
        || deletions.import(report.record.import_identity()).is_some()
        || [
            report.record.import_root,
            report.record.trace_digest,
            report.record.manifest_digest,
        ]
        .iter()
        .any(|digest| deletions.object(*digest).is_some())
    {
        return Err(HistoricalHealthError::Unavailable);
    }
    let target = slot("hh", digest)?;
    if deployment
        .publisher()
        .root(&target)
        .is_none_or(|root| root.root != report.provenance_root)
    {
        return Err(HistoricalHealthError::Unavailable);
    }
    Ok(report)
}

/// Inspect committed metadata under current custody/deletion policy without native decoding.
/// A newer mask does not erase an older historical finding; its exact historical policy remains
/// explicit. Native replay additionally requires the currently applicable policy to match.
pub fn read_retained(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    limits: &HistoricalHealthReadLimits,
    cx: &ReplayCx,
) -> Result<HistoricalHealthReadReport> {
    limits.validate()?;
    checkpoint(cx, "historical_health:read")?;
    if cx.root_dir() != deployment.root() {
        return Err(HistoricalHealthError::AuthorityChanged);
    }
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(ReferenceError::from)?;
    let mut reader = Metadata {
        deployment,
        remaining: limits.maximum_metadata_bytes,
        cx,
    };
    let report = inspect(deployment, digest, &mut reader)?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(ReferenceError::from)?;
    Ok(report)
}

/// Explicit native verification, admitting every original reservation against current ceilings
/// before source decoding. The complete original masked scan must reproduce its exact trace and
/// compact receipt. This is a historical derivation check and grants no publication authority.
pub fn verify_retained(
    deployment: &ReferenceDeployment,
    digest: ContentDigest,
    expected_provenance_root: ContentDigest,
    limits: &HistoricalHealthReadLimits,
    cx: &ReplayCx,
) -> Result<HistoricalHealthReadReport> {
    limits.validate()?;
    checkpoint(cx, "historical_health:verify")?;
    if cx.root_dir() != deployment.root() {
        return Err(HistoricalHealthError::AuthorityChanged);
    }
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(ReferenceError::from)?;
    let mut reader = Metadata {
        deployment,
        remaining: limits.maximum_metadata_bytes,
        cx,
    };
    let mut report = inspect(deployment, digest, &mut reader)?;
    if report.provenance_root != expected_provenance_root {
        return Err(HistoricalHealthError::AuthorityChanged);
    }
    super::long_dwell::limits::validate_within(&report.record.limits, &limits.execution)?;
    let privacy =
        current_mask(deployment, report.record.sensor_id()).map_err(RecordedDecodeError::from)?;
    if privacy.digest() != report.record.privacy_digest()
        || privacy.generation() != report.record.privacy_generation
    {
        return Err(HistoricalHealthError::PrivacyChanged);
    }
    let trace = reader.read(report.record.trace_digest, report.record.trace_bytes)?;
    if trace.len() != report.record.trace_bytes
        || ContentDigest::sha256(&trace) != report.record.trace_digest
    {
        return Err(HistoricalHealthError::InvalidRecord);
    }
    checkpoint(cx, "historical_health:native_replay")?;
    let scan = run_scan(
        deployment,
        &report.record.plan,
        report.record.rule,
        report.record.options,
        &report.record.limits,
        cx,
        true,
    )?;
    let reproduced = scan
        .health_diagnostic
        .as_ref()
        .ok_or(HistoricalHealthError::Diverged)?;
    if reproduced.record.to_bytes() != report.record.to_bytes() || scan.trace != trace {
        return Err(HistoricalHealthError::Diverged);
    }
    // Recheck exact source custody/privacy after native work and before reporting success.
    scan.publication_guard.revalidate(deployment, cx)?;
    checkpoint(cx, "historical_health:verified")?;
    report.native_verified = true;
    report.frames_replayed = scan.decoded;
    report.source_chunk_bytes_read = scan.source_bytes;
    Ok(report)
}

#[cfg(test)]
mod tests;
