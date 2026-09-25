#![forbid(unsafe_code)]
//! Deterministic reference deployment composition.
//!
//! Lifts the composition of [`DurableReferenceLedger`], [`LocalRootPublisher`] (with its owned
//! [`StagingSpool`](fss_object::StagingSpool)), and [`DurableEffectJournal`] into one canonical library
//! type defining a deployment root on disk.

use std::fs::{self, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CanonicalDecode, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest,
    ContractError, EventHypothesis, EventId, EvidenceDelta, EvidenceDeltaBatch, HandoffCapsule,
    HandoffId, LedgerAnchor, ObjectId, OperationReceipt, Plane, TimestampNs,
};
use fss_ledger::{
    DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, JournalError, RepairReceipt,
    doctor,
};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{
    AuthorityPublisher, LedgeredRootPublisher, LocalPublicationError, LocalPublicationLimits,
    LocalRecoveryReport, LocalRootPublisher, PublishCancellation, PublishCutPoint,
    ROOT_REACHABILITY_FAMILY, ROOT_RETRACTION_FAMILY, RootLedgerReceipt, RootLedgerReconciliation,
    SlotName,
};

use crate::adapter_replay::ReplayCx;
use crate::alert::{ReferenceAlertPlan, ReferenceAlertProvider, ReferenceProviderBehavior};
use crate::durable_effect::{DurableEffectError, DurableEffectJournal};
use crate::error::ReferenceError;
use crate::policy::{
    ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyDecision,
    evaluate_unknown_presence,
};
use crate::situation_guard::{
    ReferenceSituation, ReferenceSituationRequest,
    compile_reference_situation_with_durable_journal, seal_reference_handoff,
};

/// Canonical schema ID for reference deployment layout.
pub const DEPLOYMENT_LAYOUT_SCHEMA: &str = "fss.reference_deployment.layout.v1";
/// Format version for reference deployment layout.
pub const DEPLOYMENT_LAYOUT_FORMAT_VERSION: u32 = 1;
/// Fixed filename for layout descriptor under deployment root.
pub const DEPLOYMENT_LAYOUT_FILENAME: &str = "LAYOUT";

/// Relative path to authority ledger journal.
pub const RELATIVE_PATH_LEDGER: &str = "ledger/journal.fssj";
/// Relative path to object storage directory.
pub const RELATIVE_PATH_OBJECTS: &str = "objects";
/// Relative path to durable effect journal.
pub const RELATIVE_PATH_EFFECTS: &str = "effects/journal.fssj";

/// Registered ledger delta family: sensor capsule.
pub const FAMILY_SENSOR_CAPSULE: &str = "sensor_capsule";
/// Registered ledger delta family: event revision.
pub const FAMILY_EVENT_REVISION: &str = "event_revision";
/// Registered ledger delta family: alert effect outcome.
pub const FAMILY_ALERT_EFFECT_OUTCOME: &str = "alert_effect_outcome";
/// Reserved ledger delta family: accumulated sensor-tamper witness of an event revision.
pub const FAMILY_SENSOR_TAMPER_STATUS: &str = "sensor_tamper_status";
/// Registered ledger delta family: file import lifecycle object (generation 1 = in progress,
/// generation 2 = complete).
pub const FAMILY_FILE_IMPORT: &str = "file_import";
/// Registered ledger delta family: file import manifest.
pub const FAMILY_FILE_IMPORT_MANIFEST: &str = "file_import_manifest";
/// Registered ledger delta family: acquisition transition.
pub const FAMILY_ACQUISITION_TRANSITION: &str = "acquisition_transition";
/// Registered ledger delta family: decode receipt.
pub const FAMILY_DECODE_RECEIPT: &str = "decode_receipt";
/// Registered ledger delta family: model invocation receipt.
pub const FAMILY_MODEL_INVOCATION_RECEIPT: &str = "model_invocation_receipt";
/// Registered ledger delta family: executor model result.
pub const FAMILY_EXECUTOR_MODEL_RESULT: &str = "executor_model_result";
/// Registered ledger delta family: twin localization receipt.
pub const FAMILY_TWIN_LOCALIZATION_RECEIPT: &str = "twin_localization_receipt";
/// Registered ledger delta family: retained coverage witnesses of one analysed recording
/// (`ingest::recorded_coverage`), committed only after exact operator approval.
pub const FAMILY_COVERAGE_WITNESS: &str = "coverage_witness";
/// Registered ledger delta family: an owner-declared per-sensor privacy mask policy
/// (`ingest::privacy_mask`), one generation per exact approval; plane authority.
pub const FAMILY_PRIVACY_MASK_POLICY: &str = "privacy_mask_policy";
/// Registered ledger delta family: the sealed deletion plan of one retained import
/// ([`crate::deletion`]), appended before any byte is removed; plane authority. Reserved.
pub const FAMILY_DELETION_RECORD: &str = "deletion_record";
/// Registered ledger delta family: the successor generation of a ledger object whose content a
/// durable deletion record removed; the object's history is kept, never rewritten. Reserved.
pub const FAMILY_DELETION_TOMBSTONE: &str = "deletion_tombstone";
/// Registered ledger delta family: the deletion-completion record naming exactly what was
/// removed, retained and not provable; appended last. Reserved.
pub const FAMILY_DELETION_COMPLETION: &str = "deletion_completion";

/// Known ledger delta families table.
pub const KNOWN_LEDGER_DELTA_FAMILIES: &[&str] = &[
    FAMILY_SENSOR_CAPSULE,
    FAMILY_EVENT_REVISION,
    FAMILY_ALERT_EFFECT_OUTCOME,
    FAMILY_FILE_IMPORT,
    FAMILY_FILE_IMPORT_MANIFEST,
    FAMILY_ACQUISITION_TRANSITION,
    FAMILY_DECODE_RECEIPT,
    FAMILY_MODEL_INVOCATION_RECEIPT,
    FAMILY_EXECUTOR_MODEL_RESULT,
    FAMILY_TWIN_LOCALIZATION_RECEIPT,
    FAMILY_COVERAGE_WITNESS,
    FAMILY_PRIVACY_MASK_POLICY,
    FAMILY_DELETION_RECORD,
    FAMILY_DELETION_TOMBSTONE,
    FAMILY_DELETION_COMPLETION,
];

/// Replay cancellation stage: open deployment.
pub const STAGE_DEPLOYMENT_OPEN: &str = "deployment_open";
/// Replay cancellation stage: stage objects.
pub const STAGE_STAGE_OBJECTS: &str = "stage_objects";
/// Replay cancellation stage: stage manifest.
pub const STAGE_STAGE_MANIFEST: &str = "stage_manifest";
/// Replay cancellation stage: publish root.
pub const STAGE_PUBLISH_ROOT: &str = "publish_root";
/// Replay cancellation stage: publish event.
pub const STAGE_PUBLISH_EVENT: &str = "publish_event";
/// Replay cancellation stage: append batch.
pub const STAGE_APPEND_BATCH: &str = "append_batch";
/// Replay cancellation stage: evaluate policy.
pub const STAGE_EVALUATE_POLICY: &str = "evaluate_policy";
/// Replay cancellation stage: dispatch alert.
pub const STAGE_DISPATCH_ALERT: &str = "dispatch_alert";
/// Replay cancellation stage: compile situation.
pub const STAGE_COMPILE_SITUATION: &str = "compile_situation";
/// Replay cancellation stage: seal handoff.
pub const STAGE_SEAL_HANDOFF: &str = "seal_handoff";
/// Replay cancellation stage: publication cut point after children verified.
pub const STAGE_AFTER_CHILDREN_VERIFIED: &str = "after_children_verified";
/// Replay cancellation stage: publication cut point after manifest body.
pub const STAGE_AFTER_MANIFEST_BODY: &str = "after_manifest_body";
/// Replay cancellation stage: publication cut point after root temp write.
pub const STAGE_AFTER_ROOT_TEMP_WRITE: &str = "after_root_temp_write";
/// Replay cancellation stage: publication cut point after root rename.
pub const STAGE_AFTER_ROOT_RENAME: &str = "after_root_rename";

/// Exported list of all deployment cancellation checkpoint stages.
pub const DEPLOYMENT_CANCEL_STAGES: &[&str] = &[
    STAGE_DEPLOYMENT_OPEN,
    STAGE_STAGE_OBJECTS,
    STAGE_STAGE_MANIFEST,
    STAGE_PUBLISH_ROOT,
    STAGE_PUBLISH_EVENT,
    STAGE_APPEND_BATCH,
    STAGE_EVALUATE_POLICY,
    STAGE_DISPATCH_ALERT,
    STAGE_COMPILE_SITUATION,
    STAGE_SEAL_HANDOFF,
    STAGE_AFTER_CHILDREN_VERIFIED,
    STAGE_AFTER_MANIFEST_BODY,
    STAGE_AFTER_ROOT_TEMP_WRITE,
    STAGE_AFTER_ROOT_RENAME,
];

/// The public entry point that owns a reserved ledger delta family, or `None` if the family may
/// be appended through [`ReferenceDeployment::append_batch`].
///
/// An event revision and its sensor-tamper witness are only ever committed together by
/// `publish_event`, after the lineage tamper step; a root reachability claim only by
/// `publish_and_commit`, after the root is durable. Appending them directly would put
/// unguarded authority into the ledger.
fn reserved_family_entry_point(family: &str) -> Option<&'static str> {
    match family {
        FAMILY_EVENT_REVISION | FAMILY_SENSOR_TAMPER_STATUS => Some("publish_event"),
        ROOT_REACHABILITY_FAMILY => Some("publish_and_commit"),
        FAMILY_DELETION_RECORD
        | FAMILY_DELETION_TOMBSTONE
        | FAMILY_DELETION_COMPLETION
        | ROOT_RETRACTION_FAMILY => Some("deletion::commit_deletion"),
        _ => None,
    }
}

/// Handle to a staged manifest that has not yet been committed to authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedManifestHandle {
    /// Target publication slot.
    pub slot: SlotName,
    /// Staged object manifest.
    pub manifest: ObjectManifest,
    /// Computed manifest root.
    pub root: ContentDigest,
}

/// Validates that `site_lineage` meets token grammar constraints.
///
/// Refuses empty strings, whitespace, control characters, and non-ASCII characters.
pub fn validate_site_lineage(lineage: &str) -> Result<(), ReferenceError> {
    if lineage.is_empty() {
        return Err(ReferenceError::InvalidSpec(
            "deployment site_lineage is empty",
        ));
    }
    if lineage.contains(|c: char| c.is_whitespace() || c.is_control()) {
        return Err(ReferenceError::InvalidSpec(
            "deployment site_lineage contains whitespace or control characters",
        ));
    }
    if !lineage.chars().all(|c| c.is_ascii_graphic()) {
        return Err(ReferenceError::InvalidSpec(
            "deployment site_lineage must consist of ASCII graphic characters",
        ));
    }
    Ok(())
}

fn is_skeleton_or_empty(root: &Path) -> Result<bool, ReferenceError> {
    if !root.exists() {
        return Ok(true);
    }
    if !root.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if s == DEPLOYMENT_LAYOUT_FILENAME {
            continue;
        }
        if s.starts_with("LAYOUT.tmp.") {
            continue;
        }
        if s == "objects" {
            let path = entry.path();
            if path.is_dir() {
                for sub in fs::read_dir(&path)? {
                    let sub = sub?;
                    let sub_name = sub.file_name();
                    let sub_s = sub_name.to_string_lossy();
                    if sub_s == "LOCK" || sub_s.starts_with("LOCK.tmp.") {
                        continue;
                    }
                    if sub_s == "roots" || sub_s == "tombstones" {
                        let sub_path = sub.path();
                        if sub_path.is_dir() {
                            if fs::read_dir(&sub_path)?.next().is_some() {
                                return Ok(false);
                            }
                            continue;
                        }
                        return Ok(false);
                    }
                    if sub_s == "spool" {
                        let sub_path = sub.path();
                        if sub_path.is_dir() {
                            for inner in fs::read_dir(&sub_path)? {
                                let inner = inner?;
                                let inner_name = inner.file_name();
                                let inner_s = inner_name.to_string_lossy();
                                if inner_s == "LOCK" || inner_s.starts_with("LOCK.tmp.") {
                                    continue;
                                }
                                if (inner_s == "objects"
                                    || inner_s == "staging"
                                    || inner_s == "verified"
                                    || inner_s == "verified.tmp"
                                    || inner_s == "holds"
                                    || inner_s == "staged"
                                    || inner_s == "corrupt")
                                    && inner.path().is_dir()
                                {
                                    if fs::read_dir(inner.path())?.next().is_some() {
                                        return Ok(false);
                                    }
                                    continue;
                                }
                                return Ok(false);
                            }
                            continue;
                        }
                        return Ok(false);
                    }
                    return Ok(false);
                }
                continue;
            }
            return Ok(false);
        }
        if s == "ledger" {
            let path = entry.path();
            if path.is_dir() {
                let j = path.join("journal.fssj");
                if j.exists() && fs::metadata(&j)?.len() > 0 {
                    return Ok(false);
                }
                continue;
            }
            return Ok(false);
        }
        if s == "effects" {
            let path = entry.path();
            if path.is_dir() {
                let j = path.join("journal.fssj");
                if j.exists() && fs::metadata(&j)?.len() > 0 {
                    return Ok(false);
                }
                continue;
            }
            return Ok(false);
        }
        return Ok(false);
    }
    Ok(true)
}

const ROOT_DOMAIN: &[u8] = b"FSS-JOURNAL-RECORD-ROOT-V1\0";
const RECORD_MAGIC: [u8; 8] = *b"FSSJRN01";
const COMMIT_MAGIC: [u8; 8] = *b"FSSCMT01";
const FORMAT_VERSION: u16 = 1;
const HEADER_LEN: usize = 88;
const TRAILER_LEN: usize = 40;
const MAX_RECORD_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

fn compute_record_root(
    sequence: u64,
    kind: u16,
    payload_len: u32,
    previous_root: &[u8; 32],
    payload_digest: &[u8; 32],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(ROOT_DOMAIN.len() + 8 + 2 + 4 + 32 + 32);
    bytes.extend_from_slice(ROOT_DOMAIN);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(previous_root);
    bytes.extend_from_slice(payload_digest);
    fss_core::sha256(&bytes)
}

fn delta_order_key(delta: &EvidenceDelta) -> (&str, &str, u64, &str) {
    (
        delta.family.as_str(),
        delta.object_id.as_str(),
        delta.new_generation,
        delta.delta_id.as_str(),
    )
}

struct StagedEventRevision {
    event_root: ContentDigest,
    event_object_digest: ContentDigest,
    event_revision_digest: ContentDigest,
}

fn authority_predecessor(
    ledger: &DurableReferenceLedger,
    object_id: &ObjectId,
) -> Result<(Option<u64>, Option<ContentDigest>), ReferenceError> {
    let Some(current) = ledger.current().objects.get(object_id) else {
        return Ok((None, None));
    };

    let revision_digest = ledger
        .batches()
        .iter()
        .rev()
        .find_map(|batch| {
            batch
                .deltas
                .iter()
                .find(|delta| {
                    delta.object_id == *object_id
                        && delta.family == "event_revision"
                        && delta.new_generation == current.generation
                        && delta.payload_digest == current.payload_digest
                })
                .and_then(|delta| delta.witness_digest)
        })
        .ok_or(ContractError::SupersessionMismatch)?;

    Ok((Some(current.generation), Some(revision_digest)))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn is_structurally_valid_record(slice: &[u8]) -> bool {
    if slice.len() < HEADER_LEN + TRAILER_LEN {
        return false;
    }
    if slice[0..8] != RECORD_MAGIC {
        return false;
    }
    if read_u16(slice, 8) != FORMAT_VERSION {
        return false;
    }
    let sequence = read_u64(slice, 10);
    let kind = read_u16(slice, 18);
    let payload_len = read_u32(slice, 20);
    let payload_len_usize = match usize::try_from(payload_len) {
        Ok(len) if len <= MAX_RECORD_PAYLOAD_BYTES => len,
        _ => return false,
    };
    let total_len = HEADER_LEN + payload_len_usize + TRAILER_LEN;
    if slice.len() < total_len {
        return false;
    }
    let mut previous_root = [0_u8; 32];
    previous_root.copy_from_slice(&slice[24..56]);
    let mut named_payload_digest = [0_u8; 32];
    named_payload_digest.copy_from_slice(&slice[56..88]);

    let payload = &slice[88..88 + payload_len_usize];
    if fss_core::sha256(payload) != named_payload_digest {
        return false;
    }

    let trailer_offset = 88 + payload_len_usize;
    if slice[trailer_offset..trailer_offset + 8] != COMMIT_MAGIC {
        return false;
    }

    let mut committed_root = [0_u8; 32];
    committed_root.copy_from_slice(&slice[trailer_offset + 8..trailer_offset + 40]);

    let expected_root = compute_record_root(
        sequence,
        kind,
        payload_len,
        &previous_root,
        &named_payload_digest,
    );
    committed_root == expected_root
}

pub(crate) fn find_structurally_valid_record(
    bytes: &[u8],
    foreign_offset: u64,
    foreign_length: u64,
) -> Option<u64> {
    let start = foreign_offset as usize;
    let end = (foreign_offset.saturating_add(foreign_length)) as usize;
    if start >= bytes.len() || end > bytes.len() || start >= end {
        return None;
    }
    let slice = &bytes[start..end];
    let magic = &RECORD_MAGIC;
    for (i, window) in slice.windows(magic.len()).enumerate() {
        if window == magic {
            let candidate_slice = &slice[i..];
            if is_structurally_valid_record(candidate_slice) {
                return Some(foreign_offset + i as u64);
            }
        }
    }
    None
}

/// Explicit capacity limits bounding a reference deployment instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentLimits {
    /// Maximum size of a single spool object in bytes (default: 64 MiB).
    pub spool_object_max_bytes: u64,
    /// Maximum total spool storage across all staged objects in bytes (default: 512 MiB).
    pub spool_total_max_bytes: u64,
    /// Maximum number of children in a manifest (default: 16,384).
    pub manifest_children_max: usize,
    /// Maximum deltas or children per authority batch (default: 16,384).
    pub batch_entries_max: usize,
    /// Maximum size of a single journal record payload in bytes (default: 16 MiB).
    pub journal_record_max_bytes: u32,
    /// Maximum visible roots (default: 128).
    pub max_roots: usize,
    /// Maximum durable tombstones (default: 128).
    pub max_tombstones: usize,
    /// Maximum unique staged objects in the spool (default: 65,536).
    pub spool_max_objects: usize,
    /// Maximum entries listed from one directory on open (default: 131,072). The spool requires it
    /// to be at least `spool_max_objects`, and the publisher at least `max_roots` and
    /// `max_tombstones`; an inconsistent set is refused on open, never silently raised.
    pub scan_max_objects: usize,
}

impl Default for DeploymentLimits {
    fn default() -> Self {
        Self::standard()
    }
}

impl DeploymentLimits {
    /// Standard 64 MiB spool object maximum.
    pub const STANDARD_SPOOL_OBJECT_MAX_BYTES: u64 = 64 * 1024 * 1024;
    /// Standard 512 MiB spool total maximum.
    pub const STANDARD_SPOOL_TOTAL_MAX_BYTES: u64 = 512 * 1024 * 1024;
    /// Standard 16,384 manifest children maximum.
    pub const STANDARD_MANIFEST_CHILDREN_MAX: usize = 16_384;
    /// Standard 16,384 entries per batch maximum.
    pub const STANDARD_BATCH_ENTRIES_MAX: usize = 16_384;
    /// Standard 16 MiB journal record payload maximum.
    pub const STANDARD_JOURNAL_RECORD_MAX_BYTES: u32 = 16 * 1024 * 1024;
    /// Standard 128 visible roots maximum.
    pub const STANDARD_MAX_ROOTS: usize = 128;
    /// Standard 128 durable tombstones maximum.
    pub const STANDARD_MAX_TOMBSTONES: usize = 128;
    /// Standard 65,536 spool objects maximum.
    pub const STANDARD_SPOOL_MAX_OBJECTS: usize = 65_536;
    /// Standard 131,072 directory entries scan maximum (twice the standard spool object bound).
    ///
    /// Not a registered policy threshold: no row in `registries/*.md` or `architecture/*` names
    /// this bound or the spool object bound (checked against main 361f3fa, fss-2h5zq.9). It is a
    /// structural invariant of the owned staging spool, whose `SpoolLimits::validate` refuses
    /// a scan bound below `spool_max_objects` (`ScanBoundBelowObjectBound`); the publisher also
    /// requires it to be at least `max_roots` and `max_tombstones`. 131,072 matches
    /// `SpoolLimits::default()` for 65,536 objects. The earlier 4,096 made every standard open
    /// fail. `exported_constants_and_tables_integrity` validates the standard publication limits.
    pub const STANDARD_SCAN_MAX_OBJECTS: usize = 131_072;

    /// Standard deployment bounds.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            spool_object_max_bytes: Self::STANDARD_SPOOL_OBJECT_MAX_BYTES,
            spool_total_max_bytes: Self::STANDARD_SPOOL_TOTAL_MAX_BYTES,
            manifest_children_max: Self::STANDARD_MANIFEST_CHILDREN_MAX,
            batch_entries_max: Self::STANDARD_BATCH_ENTRIES_MAX,
            journal_record_max_bytes: Self::STANDARD_JOURNAL_RECORD_MAX_BYTES,
            max_roots: Self::STANDARD_MAX_ROOTS,
            max_tombstones: Self::STANDARD_MAX_TOMBSTONES,
            spool_max_objects: Self::STANDARD_SPOOL_MAX_OBJECTS,
            scan_max_objects: Self::STANDARD_SCAN_MAX_OBJECTS,
        }
    }

    /// Computes the canonical content digest of the deployment limits.
    pub fn canonical_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text("fss.reference_deployment.limits.v1");
        encoder.u64(self.spool_object_max_bytes);
        encoder.u64(self.spool_total_max_bytes);
        encoder.u64(self.manifest_children_max as u64);
        encoder.u64(self.batch_entries_max as u64);
        encoder.u32(self.journal_record_max_bytes);
        encoder.u64(self.max_roots as u64);
        encoder.u64(self.max_tombstones as u64);
        encoder.u64(self.spool_max_objects as u64);
        encoder.u64(self.scan_max_objects as u64);
        let bytes = encoder.finish_checked()?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Converts these limits to publication layer limits.
    #[must_use]
    pub fn to_publication_limits(&self) -> LocalPublicationLimits {
        let max_object_bytes = match usize::try_from(self.spool_object_max_bytes) {
            Ok(n) => n,
            Err(_) => usize::MAX,
        };
        let spool_scan = self.scan_max_objects;
        LocalPublicationLimits::new(
            self.max_roots,
            self.manifest_children_max,
            self.max_tombstones,
            self.scan_max_objects,
            SpoolLimits::new(
                self.spool_max_objects,
                self.spool_total_max_bytes,
                max_object_bytes,
                spool_scan,
            ),
        )
    }
}

/// Read-only deployment layout report and on-disk descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentLayout {
    /// Schema identity (`fss.reference_deployment.layout.v1`).
    pub schema: String,
    /// Layout format version.
    pub format_version: u32,
    /// Site lineage identifier.
    pub site_lineage: String,
    /// Relative path to authority ledger journal.
    pub ledger_relpath: String,
    /// Relative path to object storage directory.
    pub objects_relpath: String,
    /// Relative path to durable effect journal.
    pub effects_relpath: String,
    /// Canonical digest of the deployment capacity limits.
    pub limits_digest: ContentDigest,
}

impl DeploymentLayout {
    /// Constructs a standard layout specification with the given lineage and limits digest.
    #[must_use]
    pub fn new(site_lineage: &str, limits_digest: ContentDigest) -> Self {
        Self {
            schema: DEPLOYMENT_LAYOUT_SCHEMA.to_owned(),
            format_version: DEPLOYMENT_LAYOUT_FORMAT_VERSION,
            site_lineage: site_lineage.to_owned(),
            ledger_relpath: RELATIVE_PATH_LEDGER.to_owned(),
            objects_relpath: RELATIVE_PATH_OBJECTS.to_owned(),
            effects_relpath: RELATIVE_PATH_EFFECTS.to_owned(),
            limits_digest,
        }
    }

    /// Computes the canonical content digest of the layout.
    pub fn canonical_digest(&self) -> Result<ContentDigest, ContractError> {
        let mut encoder = CanonicalEncoder::new();
        encoder.text(DEPLOYMENT_LAYOUT_SCHEMA);
        encoder.u32(self.format_version);
        encoder.text(&self.site_lineage);
        encoder.text(&self.ledger_relpath);
        encoder.text(&self.objects_relpath);
        encoder.text(&self.effects_relpath);
        encoder.digest(self.limits_digest);
        let bytes = encoder.finish_checked()?;
        Ok(ContentDigest::sha256(&bytes))
    }

    /// Serializes to canonical text for writing to the LAYOUT file.
    #[must_use]
    pub fn to_canonical_text(&self) -> String {
        format!(
            "schema={}\nversion={}\nsite_lineage={}\nledger={}\nobjects={}\neffects={}\nlimits_digest={}\n",
            self.schema,
            self.format_version,
            self.site_lineage,
            self.ledger_relpath,
            self.objects_relpath,
            self.effects_relpath,
            self.limits_digest.to_text()
        )
    }

    /// Parses canonical text from the LAYOUT file.
    pub fn parse_canonical_text(text: &str) -> Result<Self, ReferenceError> {
        let mut schema = None;
        let mut version = None;
        let mut site_lineage = None;
        let mut ledger = None;
        let mut objects = None;
        let mut effects = None;
        let mut limits_digest = None;

        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                return Err(ReferenceError::InvalidSpec(
                    "layout line must use '=' separator",
                ));
            };

            match key {
                "schema" => {
                    if schema.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: schema"));
                    }
                    schema = Some(value.to_owned());
                }
                "version" => {
                    if version.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: version"));
                    }
                    let v = value.parse::<u32>().map_err(|_| {
                        ReferenceError::InvalidSpec("invalid layout format version")
                    })?;
                    version = Some(v);
                }
                "site_lineage" => {
                    if site_lineage.is_some() {
                        return Err(ReferenceError::InvalidSpec(
                            "duplicate layout key: site_lineage",
                        ));
                    }
                    validate_site_lineage(value)?;
                    site_lineage = Some(value.to_owned());
                }
                "ledger" => {
                    if ledger.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: ledger"));
                    }
                    if value != RELATIVE_PATH_LEDGER {
                        return Err(ReferenceError::InvalidSpec("invalid layout ledger relpath"));
                    }
                    ledger = Some(value.to_owned());
                }
                "objects" => {
                    if objects.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: objects"));
                    }
                    if value != RELATIVE_PATH_OBJECTS {
                        return Err(ReferenceError::InvalidSpec(
                            "invalid layout objects relpath",
                        ));
                    }
                    objects = Some(value.to_owned());
                }
                "effects" => {
                    if effects.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: effects"));
                    }
                    if value != RELATIVE_PATH_EFFECTS {
                        return Err(ReferenceError::InvalidSpec(
                            "invalid layout effects relpath",
                        ));
                    }
                    effects = Some(value.to_owned());
                }
                "limits_digest" => {
                    if limits_digest.is_some() {
                        return Err(ReferenceError::InvalidSpec(
                            "duplicate layout key: limits_digest",
                        ));
                    }
                    let digest = ContentDigest::parse(value)
                        .map_err(|_| ReferenceError::InvalidSpec("invalid layout limits digest"))?;
                    limits_digest = Some(digest);
                }
                _ => return Err(ReferenceError::InvalidSpec("unknown layout key")),
            }
        }

        let schema = schema.ok_or(ReferenceError::InvalidSpec("missing layout schema"))?;
        let version = version.ok_or(ReferenceError::InvalidSpec("missing layout version"))?;
        let site_lineage =
            site_lineage.ok_or(ReferenceError::InvalidSpec("missing layout site lineage"))?;
        let ledger = ledger.ok_or(ReferenceError::InvalidSpec("missing layout ledger"))?;
        let objects = objects.ok_or(ReferenceError::InvalidSpec("missing layout objects"))?;
        let effects = effects.ok_or(ReferenceError::InvalidSpec("missing layout effects"))?;
        let limits_digest =
            limits_digest.ok_or(ReferenceError::InvalidSpec("missing layout limits digest"))?;

        if schema != DEPLOYMENT_LAYOUT_SCHEMA {
            return Err(ReferenceError::InvalidSpec("incompatible layout schema"));
        }
        if version != DEPLOYMENT_LAYOUT_FORMAT_VERSION {
            return Err(ReferenceError::InvalidSpec("incompatible layout version"));
        }

        let layout = Self {
            schema,
            format_version: version,
            site_lineage,
            ledger_relpath: ledger,
            objects_relpath: objects,
            effects_relpath: effects,
            limits_digest,
        };

        if layout.to_canonical_text() != text {
            return Err(ReferenceError::InvalidSpec("layout text is not canonical"));
        }

        Ok(layout)
    }
}

/// Filesystem boundary for the two commit steps of [`write_layout_atomic`].
///
/// The temporary descriptor is always written and fsynced through the host filesystem. The two
/// steps that decide visibility and durability, the rename onto `LAYOUT` and the fsync of the
/// deployment root directory, go through this trait, so a failure-path test injects an error at
/// either step through a value it owns and no process-wide state is involved.
pub trait LayoutIo {
    /// Atomically renames `from` onto `to`.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    /// Fsyncs the directory `dir` so a rename inside it is durable.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;
}

/// The host filesystem implementation of [`LayoutIo`]; [`ReferenceDeployment::open`] uses it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostLayoutIo;

impl LayoutIo for HostLayoutIo {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        let dir = fs::File::open(dir)?;
        dir.sync_all()
    }
}

/// Writes `layout` as `<root>/LAYOUT` atomically.
///
/// The canonical text is written to `LAYOUT.tmp.<pid>` and fsynced, renamed onto `LAYOUT` through
/// `io`, and the root directory is then fsynced through `io`. Pass [`HostLayoutIo`] outside tests.
///
/// A failure before or at the rename leaves any previous `LAYOUT` byte-identical; the temporary
/// file stays behind and the next open removes it under the deployment lock. A failed directory
/// fsync after the rename is returned as an error: the new descriptor is visible, but its
/// durability is not proven, so the write is never reported as complete.
///
/// # Errors
///
/// [`ReferenceError::InvalidSpec`] if the site lineage is invalid (nothing is written), and
/// [`ReferenceError::Io`] for any filesystem failure, including one injected through `io`.
pub fn write_layout_atomic(
    root: &Path,
    layout: &DeploymentLayout,
    io: &dyn LayoutIo,
) -> Result<(), ReferenceError> {
    validate_site_lineage(&layout.site_lineage)?;
    let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
    let temp_path = root.join(format!(
        "{}.tmp.{}",
        DEPLOYMENT_LAYOUT_FILENAME,
        std::process::id()
    ));
    let text = layout.to_canonical_text();
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    io.rename(&temp_path, &layout_path)?;
    io.sync_dir(root)?;
    Ok(())
}

/// Recovery action requested when invoking [`ReferenceDeployment::open_for_recovery`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// Truncate an incomplete record tail from the authority ledger journal.
    TruncateIncompleteLedgerTail,
    /// Truncate an incomplete record tail from the durable effect journal.
    TruncateIncompleteEffectTail,
    /// Apply a pre-computed sealed repair plan to quarantine trailing foreign bytes in the ledger.
    ApplySealedLedgerRepair {
        /// Expected plan digest.
        plan_digest: ContentDigest,
    },
    /// Apply a pre-computed sealed repair plan to quarantine trailing foreign bytes in the effect journal.
    ApplySealedEffectRepair {
        /// Expected plan digest.
        plan_digest: ContentDigest,
    },
}

/// Typed receipt produced by an explicit recovery action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryReceipt {
    /// Incomplete ledger tail was truncated.
    TruncatedLedgerTail {
        /// Journal path.
        path: PathBuf,
        /// File offset through the last complete committed record.
        committed_len: u64,
        /// Number of incomplete trailing bytes truncated.
        truncated_bytes: u64,
        /// Last root digest before truncation.
        last_root_before: ContentDigest,
        /// Last root digest after truncation.
        last_root_after: ContentDigest,
    },
    /// Incomplete effect tail was truncated.
    TruncatedEffectTail {
        /// Journal path.
        path: PathBuf,
        /// File offset through the last complete committed record.
        committed_len: u64,
        /// Number of incomplete trailing bytes truncated.
        truncated_bytes: u64,
        /// Last root digest before truncation.
        last_root_before: ContentDigest,
        /// Last root digest after truncation.
        last_root_after: ContentDigest,
    },
    /// Sealed ledger repair plan was applied.
    AppliedLedgerRepair(RepairReceipt),
    /// Sealed effect repair plan was applied.
    AppliedEffectRepair(RepairReceipt),
}

/// Registered deployment stage name of a publication cut point.
///
/// Every value is a member of [`DEPLOYMENT_CANCEL_STAGES`].
pub(crate) const fn publish_cut_point_stage(point: PublishCutPoint) -> &'static str {
    match point {
        PublishCutPoint::AfterChildrenVerified => STAGE_AFTER_CHILDREN_VERIFIED,
        PublishCutPoint::AfterManifestBody => STAGE_AFTER_MANIFEST_BODY,
        PublishCutPoint::AfterRootTempWrite => STAGE_AFTER_ROOT_TEMP_WRITE,
        PublishCutPoint::AfterRootRename => STAGE_AFTER_ROOT_RENAME,
    }
}

/// Cancellation probe bridging [`ReplayCx`] to [`PublishCancellation`].
///
/// The local publisher polls it at each pre-commit cut point. The context records that it reached
/// the cut point's registered stage, and a requested cancellation is drained and finalized before
/// the publisher is told to stop.
#[derive(Debug)]
pub struct ReplayCancellationBridge<'a>(pub &'a ReplayCx);

impl PublishCancellation for ReplayCancellationBridge<'_> {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        self.0.reach_stage(publish_cut_point_stage(point));
        if self.0.is_cancelled() {
            self.0.drain_and_finalize();
            true
        } else {
            false
        }
    }
}

/// A unified reference deployment root on disk.
#[derive(Debug)]
pub struct ReferenceDeployment {
    root: PathBuf,
    site_lineage: String,
    limits: DeploymentLimits,
    ledger: DurableReferenceLedger,
    publisher: LocalRootPublisher,
    effects: DurableEffectJournal,
    layout: DeploymentLayout,
    alert_provider: ReferenceAlertProvider,
}

impl ReferenceDeployment {
    /// Opens or reopens a reference deployment with standard publication limits.
    pub fn open(root: &Path, site_lineage: &str, cx: &ReplayCx) -> Result<Self, ReferenceError> {
        Self::open_with_limits(root, site_lineage, DeploymentLimits::standard(), cx)
    }

    /// Reopens an existing reference deployment root.
    pub fn reopen(root: &Path, site_lineage: &str, cx: &ReplayCx) -> Result<Self, ReferenceError> {
        Self::open(root, site_lineage, cx)
    }

    /// Opens or reopens a reference deployment with explicit capacity limits.
    pub fn open_with_limits(
        root: &Path,
        site_lineage: &str,
        limits: DeploymentLimits,
        cx: &ReplayCx,
    ) -> Result<Self, ReferenceError> {
        Self::open_with_after_lock(root, site_lineage, limits, cx, &|_: &Path| {})
    }

    /// [`Self::open_with_limits`] with `after_lock` invoked on `root` right after the deployment
    /// lock is taken and before the authoritative classification under it.
    ///
    /// Crate-internal failure-path seam: a test makes a foreign file appear between the advisory
    /// pre-check and the lock, and proves the classification under the lock refuses it.
    pub(crate) fn open_with_after_lock(
        root: &Path,
        site_lineage: &str,
        limits: DeploymentLimits,
        cx: &ReplayCx,
        after_lock: &dyn Fn(&Path),
    ) -> Result<Self, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_DEPLOYMENT_OPEN,
            });
        }

        validate_site_lineage(site_lineage)?;

        let root_buf = root.to_path_buf();
        // A regular file, a symlink to one, or a dangling symlink is never a deployment root.
        if fs::symlink_metadata(root).is_ok() && !root.is_dir() {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }

        let ledger_path = root.join(RELATIVE_PATH_LEDGER);
        let objects_dir = root.join(RELATIVE_PATH_OBJECTS);
        let effects_path = root.join(RELATIVE_PATH_EFFECTS);
        let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);

        // Advisory pre-check before anything is created, so a foreign directory is refused with
        // zero side effects. The authoritative check is repeated under the deployment lock below.
        if root.exists() && !layout_path.exists() && !is_skeleton_or_empty(root)? {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }

        if !root.exists() {
            fs::create_dir_all(root)?;
        }
        fs::create_dir_all(&objects_dir)?;

        // 1. Open local root publisher first: exclusive lock prevents concurrent access.
        // A second open refused here never touches or mutates either journal.
        let pub_limits = limits.to_publication_limits();
        // Every refusal goes through the typed `From<LocalPublicationError>` mapping: a held lock
        // becomes `DeploymentLocked`, and an overfull bounded directory scan `ScanLimitExceeded`.
        let publisher = LocalRootPublisher::open(&objects_dir, pub_limits)?;
        after_lock(root);

        // 2. Initialize or verify layout descriptor atomically.
        // Authoritative classification under the lock, before any cleanup or write: a root without
        // LAYOUT must still be empty or a bare deployment skeleton.
        if !layout_path.exists() && !is_skeleton_or_empty(root)? {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("LAYOUT.tmp.") {
                fs::remove_file(entry.path())?;
            }
        }
        let limits_digest = limits.canonical_digest()?;
        let layout = if layout_path.exists() {
            let content = fs::read_to_string(&layout_path)?;
            let parsed = DeploymentLayout::parse_canonical_text(&content)?;
            if parsed.site_lineage != site_lineage {
                return Err(ReferenceError::SiteLineageMismatch {
                    expected: site_lineage.to_owned(),
                    actual: parsed.site_lineage,
                });
            }
            if parsed.limits_digest != limits_digest {
                return Err(ReferenceError::LimitsDigestMismatch {
                    expected: limits_digest,
                    actual: parsed.limits_digest,
                });
            }
            parsed
        } else {
            let new_layout = DeploymentLayout::new(site_lineage, limits_digest);
            write_layout_atomic(root, &new_layout, &HostLayoutIo)?;
            new_layout
        };

        if let Some(parent) = ledger_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = effects_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // 3. Open durable authority ledger: reject incomplete tails on open.
        let ledger = match DurableReferenceLedger::open(
            &ledger_path,
            site_lineage,
            IncompleteTailPolicy::Reject,
        ) {
            Ok(l) => l,
            Err(DurableLedgerError::Journal(JournalError::IncompleteTail { offset })) => {
                return Err(ReferenceError::IncompleteJournalTail {
                    offset,
                    path: ledger_path,
                    next_affordance: format!(
                        "fss-lab recover --root {} --truncate-ledger-tail",
                        root.display()
                    ),
                });
            }
            Err(other) => return Err(ReferenceError::DurableLedger(Box::new(other))),
        };

        // 4. Open durable effect journal: reject incomplete tails on open.
        let effects = match DurableEffectJournal::open(&effects_path, IncompleteTailPolicy::Reject)
        {
            Ok(e) => e,
            Err(DurableEffectError::Journal(JournalError::IncompleteTail { offset })) => {
                return Err(ReferenceError::IncompleteJournalTail {
                    offset,
                    path: effects_path,
                    next_affordance: format!(
                        "fss-lab recover --root {} --truncate-effect-tail",
                        root.display()
                    ),
                });
            }
            Err(other) => return Err(ReferenceError::DurableEffect(Box::new(other))),
        };

        let alert_provider = ReferenceAlertProvider::new(format!("alert:{}", site_lineage));

        Ok(Self {
            root: root_buf,
            site_lineage: site_lineage.to_owned(),
            limits,
            ledger,
            publisher,
            effects,
            layout,
            alert_provider,
        })
    }

    /// Performs an explicit recovery action on a deployment root while holding the deployment lock.
    ///
    /// Never creates LAYOUT on an uninitialized root. Refuses recovery if foreign bytes contain
    /// a structurally valid committed record.
    pub fn open_for_recovery(
        root: &Path,
        action: RecoveryAction,
        cx: &ReplayCx,
    ) -> Result<RecoveryReceipt, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_DEPLOYMENT_OPEN,
            });
        }

        let root_buf = root.to_path_buf();
        if !root.exists() || !root.is_dir() {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }

        let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);

        // Acquire exclusive deployment lock on <root>/objects/LOCK for the whole recovery duration.
        // open_for_recovery must NOT create objects/.
        let objects_dir = root.join(RELATIVE_PATH_OBJECTS);
        if !objects_dir.exists() || !objects_dir.is_dir() {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }
        let lock_path = objects_dir.join("LOCK");
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(ReferenceError::LocalPublication(Box::new(
                    LocalPublicationError::InvalidLayout { path: lock_path },
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ReferenceError::Io(error)),
        }
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)?;
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(ReferenceError::DeploymentLocked { path: lock_path });
            }
            Err(TryLockError::Error(e)) => return Err(ReferenceError::Io(e)),
        }

        // Under lock: clean up stale LAYOUT.tmp.*
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("LAYOUT.tmp.") {
                fs::remove_file(entry.path())?;
            }
        }

        // Verify layout descriptor exists and is valid; open_for_recovery never creates LAYOUT.
        let layout = if layout_path.exists() {
            let content = fs::read_to_string(&layout_path)?;
            DeploymentLayout::parse_canonical_text(&content)?
        } else {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        };

        match action {
            RecoveryAction::TruncateIncompleteLedgerTail => {
                let target_path = root.join(RELATIVE_PATH_LEDGER);
                if !target_path.exists() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let pre_report = fss_ledger::inspect(&target_path)?;
                if pre_report.incomplete_tail().is_none() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let total_len = fs::metadata(&target_path)?.len();
                let committed_len = pre_report.committed_len();
                let truncated_bytes = total_len.saturating_sub(committed_len);
                let last_root_before = pre_report.last_root();
                let _opened = DurableReferenceLedger::open(
                    &target_path,
                    &layout.site_lineage,
                    IncompleteTailPolicy::Truncate,
                )?;
                let post_report = fss_ledger::inspect(&target_path)?;
                let last_root_after = post_report.last_root();
                Ok(RecoveryReceipt::TruncatedLedgerTail {
                    path: target_path,
                    committed_len,
                    truncated_bytes,
                    last_root_before,
                    last_root_after,
                })
            }
            RecoveryAction::TruncateIncompleteEffectTail => {
                let target_path = root.join(RELATIVE_PATH_EFFECTS);
                if !target_path.exists() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let pre_report = fss_ledger::inspect(&target_path)?;
                if pre_report.incomplete_tail().is_none() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let total_len = fs::metadata(&target_path)?.len();
                let committed_len = pre_report.committed_len();
                let truncated_bytes = total_len.saturating_sub(committed_len);
                let last_root_before = pre_report.last_root();
                let _opened =
                    DurableEffectJournal::open(&target_path, IncompleteTailPolicy::Truncate)?;
                let post_report = fss_ledger::inspect(&target_path)?;
                let last_root_after = post_report.last_root();
                Ok(RecoveryReceipt::TruncatedEffectTail {
                    path: target_path,
                    committed_len,
                    truncated_bytes,
                    last_root_before,
                    last_root_after,
                })
            }
            RecoveryAction::ApplySealedLedgerRepair { plan_digest } => {
                let target_path = root.join(RELATIVE_PATH_LEDGER);
                let bytes = fs::read(&target_path)?;
                let report = doctor(&bytes)?;
                let foreign = report
                    .foreign_range()
                    .ok_or(fss_ledger::RepairError::NoForeignBytes)?;

                if let Some(offset) =
                    find_structurally_valid_record(&bytes, foreign.offset, foreign.length)
                {
                    return Err(ReferenceError::RecoverCorruptHistory {
                        path: target_path,
                        offset,
                    });
                }

                let plan = report.plan(&target_path)?;
                if plan.plan_digest() != plan_digest {
                    return Err(ReferenceError::PlanDigestMismatch {
                        expected: plan_digest,
                        actual: plan.plan_digest(),
                    });
                }
                let receipt = plan.apply()?;
                Ok(RecoveryReceipt::AppliedLedgerRepair(receipt))
            }
            RecoveryAction::ApplySealedEffectRepair { plan_digest } => {
                let target_path = root.join(RELATIVE_PATH_EFFECTS);
                let bytes = fs::read(&target_path)?;
                let report = doctor(&bytes)?;
                let foreign = report
                    .foreign_range()
                    .ok_or(fss_ledger::RepairError::NoForeignBytes)?;

                if let Some(offset) =
                    find_structurally_valid_record(&bytes, foreign.offset, foreign.length)
                {
                    return Err(ReferenceError::RecoverCorruptHistory {
                        path: target_path,
                        offset,
                    });
                }

                let plan = report.plan(&target_path)?;
                if plan.plan_digest() != plan_digest {
                    return Err(ReferenceError::PlanDigestMismatch {
                        expected: plan_digest,
                        actual: plan.plan_digest(),
                    });
                }
                let receipt = plan.apply()?;
                Ok(RecoveryReceipt::AppliedEffectRepair(receipt))
            }
        }
    }

    /// Stages child payload bytes and the manifest for `slot` without making anything visible.
    ///
    /// Stage-only: every child is staged in the deployment spool and the manifest body is staged
    /// in the local publisher, but no root record is written and the ledger is untouched. The
    /// returned [`StagedManifestHandle`] becomes visible only through [`Self::publish_and_commit`],
    /// which publishes root-last and commits reachability to the canonical ledger.
    pub fn stage_and_publish(
        &mut self,
        slot: &SlotName,
        objects: &[&[u8]],
        cx: &ReplayCx,
    ) -> Result<StagedManifestHandle, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_STAGE_OBJECTS,
            });
        }

        if objects.len() > self.limits.manifest_children_max {
            return Err(ReferenceError::CapacityExceeded {
                limit: "manifest_children_max",
                maximum: self.limits.manifest_children_max as u64,
                actual: objects.len() as u64,
            });
        }

        let mut child_digests = Vec::with_capacity(objects.len());
        for obj in objects {
            if cx.is_cancelled() {
                cx.drain_and_finalize();
                return Err(ReferenceError::CancellationRequested {
                    stage: STAGE_STAGE_OBJECTS,
                });
            }
            if obj.len() as u64 > self.limits.spool_object_max_bytes {
                return Err(ReferenceError::CapacityExceeded {
                    limit: "spool_object_max_bytes",
                    maximum: self.limits.spool_object_max_bytes,
                    actual: obj.len() as u64,
                });
            }
            let digest = self.publisher.stage_object(obj)?;
            child_digests.push(digest);
        }

        cx.reach_stage(STAGE_STAGE_MANIFEST);
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_STAGE_MANIFEST,
            });
        }

        let manifest = ObjectManifest::new(slot.as_str(), child_digests, None)?;
        let manifest_root = self.publisher.stage_manifest(slot, &manifest)?;

        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_PUBLISH_ROOT,
            });
        }

        Ok(StagedManifestHandle {
            slot: slot.clone(),
            manifest,
            root: manifest_root,
        })
    }

    /// Publishes a manifest into `slot` root-last and commits its reachability to the canonical ledger.
    ///
    /// `cx` is checked before any work and polled again at every pre-commit publication cut point
    /// (`after_children_verified`, `after_manifest_body`, `after_root_temp_write`). A cancellation
    /// there returns [`ReferenceError::CancellationRequested`] naming that stage, removes any
    /// temporary root record, and leaves the ledger unchanged. The rename is the commit point:
    /// cancellation is never honored after it, so the root becomes durable and is ledgered.
    pub fn publish_and_commit(
        &mut self,
        slot: &SlotName,
        manifest: &ObjectManifest,
        validity: CaptureInterval,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_PUBLISH_ROOT,
            });
        }

        let bridge = ReplayCancellationBridge(cx);
        let mut ledgered = LedgeredRootPublisher::new(&mut self.publisher, &mut self.ledger);
        let receipt = ledgered.publish_and_commit_cancellable(slot, manifest, validity, &bridge)?;
        Ok(receipt)
    }

    /// Prepares and commits an authority batch to the canonical ledger, verifying child custody.
    ///
    /// The reserved families `event_revision` and `sensor_tamper_status` (use
    /// [`Self::publish_event`]) and `local_root_reachability` (use [`Self::publish_and_commit`])
    /// are refused with [`ReferenceError::ReservedDeltaFamily`] before any work.
    ///
    /// Idempotent by `batch_id`: when the ledger already holds this batch identity with identical
    /// deltas and children, returns the committed anchor without re-preparing deltas. If the batch
    /// identity exists with different content, refuses with [`DurableLedgerError::BatchIdConflict`].
    pub fn append_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }

        // Reserved families are committed only by their guarded entry points; refused before
        // any custody work, preparation, or journal I/O.
        if let Some((family, entry_point)) = deltas.iter().find_map(|delta| {
            reserved_family_entry_point(&delta.family).map(|entry| (delta.family.clone(), entry))
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family,
                entry_point,
            });
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    /// Crate-internal entry of the deletion-closure owner ([`crate::deletion`]): appends a batch
    /// whose deltas may carry only the deletion-reserved families (deletion record, tombstone,
    /// completion, root retraction), with every other check of [`Self::append_batch`]. Any other
    /// reserved family is still refused.
    pub(crate) fn append_deletion_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
        cx: &ReplayCx,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_APPEND_BATCH,
            });
        }
        if let Some((family, entry_point)) = deltas.iter().find_map(|delta| {
            reserved_family_entry_point(&delta.family)
                .filter(|entry| *entry != "deletion::commit_deletion")
                .map(|entry| (delta.family.clone(), entry))
        }) {
            return Err(ReferenceError::ReservedDeltaFamily {
                family,
                entry_point,
            });
        }
        self.append_checked_batch(batch_id, deltas, children)
    }

    fn append_checked_batch(
        &mut self,
        batch_id: BatchId,
        deltas: Vec<EvidenceDelta>,
        children: Vec<ContentDigest>,
    ) -> Result<LedgerAnchor, ReferenceError> {
        if deltas.len() > self.limits.batch_entries_max {
            return Err(ReferenceError::CapacityExceeded {
                limit: "batch_entries_max",
                maximum: self.limits.batch_entries_max as u64,
                actual: deltas.len() as u64,
            });
        }
        if children.len() > self.limits.batch_entries_max {
            return Err(ReferenceError::CapacityExceeded {
                limit: "batch_entries_max",
                maximum: self.limits.batch_entries_max as u64,
                actual: children.len() as u64,
            });
        }

        let mut deltas = deltas;
        deltas.sort_by(|left, right| delta_order_key(left).cmp(&delta_order_key(right)));
        let mut children = children;
        children.sort_unstable();
        children.dedup();

        // Idempotency check: check if batch_id already exists in ledger history.
        if let Some(existing) = self
            .ledger
            .batches()
            .iter()
            .find(|batch| batch.batch_id == batch_id)
        {
            if existing.deltas == deltas && existing.children == children {
                return Ok(existing.new_anchor.clone());
            }
            let candidate_batch = EvidenceDeltaBatch {
                batch_id: batch_id.clone(),
                basis_anchor: existing.basis_anchor.clone(),
                new_anchor: existing.new_anchor.clone(),
                deltas: deltas.clone(),
                children: children.clone(),
                batch_digest: ContentDigest::sha256(b""),
            };
            let offered_digest = candidate_batch.computed_digest();
            return Err(DurableLedgerError::BatchIdConflict {
                batch_id: existing.batch_id.clone(),
                committed_sequence: existing.new_anchor.commit_sequence,
                committed_digest: existing.batch_digest,
                offered_digest,
            }
            .into());
        }

        // Bound the journal record before any custody work or preparation. `prepare_batch` derives
        // the successor anchor from the current one by changing only fixed-width fields (commit
        // sequence and state root), so a candidate that carries the current anchor as both basis
        // and successor encodes to exactly the length of the batch that would be appended.
        let current_anchor = self.ledger.current().anchor.clone();
        let mut candidate = EvidenceDeltaBatch {
            batch_id: batch_id.clone(),
            basis_anchor: current_anchor.clone(),
            new_anchor: current_anchor,
            deltas: deltas.clone(),
            children: children.clone(),
            batch_digest: ContentDigest::sha256(b""),
        };
        candidate.batch_digest = candidate.computed_digest();
        let encoded = fss_ledger::encode_batch(&candidate)
            .map_err(|e| ReferenceError::DurableLedger(Box::new(DurableLedgerError::Codec(e))))?;
        if encoded.len() > self.limits.journal_record_max_bytes as usize {
            return Err(ReferenceError::CapacityExceeded {
                limit: "journal_record_max_bytes",
                maximum: self.limits.journal_record_max_bytes as u64,
                actual: encoded.len() as u64,
            });
        }

        for child in &children {
            self.publisher.verify_object(*child)?;
        }
        for delta in &deltas {
            self.publisher.verify_object(delta.payload_digest)?;
            if let Some(witness) = delta.witness_digest {
                self.publisher.verify_object(witness)?;
            }
        }

        let mut auth = AuthorityPublisher::new(&self.publisher, &mut self.ledger);
        let batch = auth.prepare_batch(batch_id, deltas, children)?;
        let anchor = auth.append(batch)?;
        Ok(anchor)
    }

    /// Stages a single object payload into the spool and returns its content digest.
    pub fn stage_payload(&mut self, bytes: &[u8]) -> Result<ContentDigest, ReferenceError> {
        if bytes.len() as u64 > self.limits.spool_object_max_bytes {
            return Err(ReferenceError::CapacityExceeded {
                limit: "spool_object_max_bytes",
                maximum: self.limits.spool_object_max_bytes,
                actual: bytes.len() as u64,
            });
        }
        let digest = self.publisher.stage_object(bytes)?;
        Ok(digest)
    }

    /// Returns a borrow-scoped [`LedgeredRootPublisher`] over this deployment's publisher and ledger.
    pub fn ledgered_publisher<'a>(&'a mut self) -> LedgeredRootPublisher<'a> {
        LedgeredRootPublisher::new(&mut self.publisher, &mut self.ledger)
    }

    /// Classifies visible roots against ledger reachability claims.
    pub fn reconcile(&mut self) -> Result<RootLedgerReconciliation, ReferenceError> {
        let ledgered = LedgeredRootPublisher::new(&mut self.publisher, &mut self.ledger);
        Ok(ledgered.reconcile()?)
    }

    /// Evaluates unknown presence policy over model observations.
    pub fn evaluate_policy(
        &self,
        event_id: EventId,
        observations: Vec<ReferenceModelObservation>,
        cx: &ReplayCx,
    ) -> Result<ReferencePolicyDecision, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_EVALUATE_POLICY,
            });
        }
        evaluate_unknown_presence(event_id, observations)
    }

    /// Publishes a reference event decision into authority.
    pub fn publish_event(
        &mut self,
        decision: &ReferencePolicyDecision,
        cx: &ReplayCx,
    ) -> Result<ReferenceEventReceipt, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_PUBLISH_EVENT,
            });
        }
        decision.event.validate()?;
        let event_name = decision.event.event_id.as_str();
        let object_id = ObjectId::parse(format!("object:event:{event_name}"))?;
        let (prior_generation, predecessor) = authority_predecessor(&self.ledger, &object_id)?;
        let candidate_revision_digest = decision.event.revision_digest();

        // Sensor tamper is sticky across the lineage (fss-2uftm), recomputed from the revisions
        // this deployment's ledger published and its spool holds, exactly as
        // `publish_reference_event` does. It applies to idempotent retries too: an exact retry of
        // a revision that drops an unretired tamper is still refused.
        let prior_events = self.prior_event_revisions(&object_id, decision.event.revision)?;
        let prior_tamper = fss_core::event::compute_sensor_tamper_status(prior_events.iter(), None);
        let mut combined_tamper = prior_tamper.clone();
        fss_core::event::apply_revision_tamper_step(&mut combined_tamper, &decision.event)?;
        if decision
            .event
            .evidence
            .iter()
            .any(|evidence| evidence.reports_integrity_restoration())
            && prior_tamper.open_tamper_records.is_empty()
        {
            return Err(ContractError::EvidenceRequired.into());
        }
        let prior_revision_encodings: Vec<Vec<u8>> = prior_events
            .iter()
            .map(crate::alert::event_revision_encoding)
            .collect();

        if predecessor == Some(candidate_revision_digest) {
            let (committed_anchor, payload_digest) = self
                .ledger
                .batches()
                .iter()
                .rev()
                .find_map(|batch| {
                    batch
                        .deltas
                        .iter()
                        .find(|delta| {
                            delta.object_id == object_id
                                && delta.family == "event_revision"
                                && delta.new_generation == decision.event.revision
                                && delta.witness_digest == Some(candidate_revision_digest)
                        })
                        .map(|delta| (batch.new_anchor.clone(), delta.payload_digest))
                })
                .ok_or(ContractError::SupersessionMismatch)?;

            let staged = self.stage_event_revision(decision)?;
            if staged.event_root != payload_digest {
                return Err(ContractError::SupersessionMismatch.into());
            }
            self.publisher.verify_object(staged.event_root)?;
            self.stage_tamper_status(&combined_tamper)?;

            return Ok(ReferenceEventReceipt {
                event_root: staged.event_root,
                event_object_digest: staged.event_object_digest,
                event_revision_digest: staged.event_revision_digest,
                authority_anchor: committed_anchor,
                lineage_tamper_status: combined_tamper,
                prior_revision_encodings,
            });
        }

        if decision.event.supersedes != predecessor {
            return Err(ContractError::SupersessionMismatch.into());
        }

        let staged = self.stage_event_revision(decision)?;
        self.stage_tamper_status(&combined_tamper)?;

        let delta = EvidenceDelta {
            delta_id: format!("delta:event:{event_name}:{}", decision.event.revision),
            family: "event_revision".to_owned(),
            object_id,
            prior_generation,
            new_generation: decision.event.revision,
            validity: decision.event.interval,
            plane: Plane::Authority,
            payload_digest: staged.event_root,
            witness_digest: Some(staged.event_revision_digest),
            operation_id: None,
        };
        // The accumulated tamper status is witnessed in the same batch; alert preparation,
        // dispatch and situation compilation cross-check it against their own recomputation.
        let tamper_delta = EvidenceDelta {
            delta_id: format!(
                "delta:event:{event_name}:tamper:{}",
                decision.event.revision
            ),
            family: "sensor_tamper_status".to_owned(),
            object_id: ObjectId::parse(format!("object:event:{event_name}:tamper"))?,
            prior_generation,
            new_generation: decision.event.revision,
            validity: decision.event.interval,
            plane: Plane::Authority,
            payload_digest: staged.event_root,
            witness_digest: Some(combined_tamper.canonical_digest()),
            operation_id: None,
        };

        let authority_anchor = {
            let mut publisher = AuthorityPublisher::new(&self.publisher, &mut self.ledger);
            let batch = publisher.prepare_batch(
                BatchId::parse(format!(
                    "batch:event:{event_name}:{}",
                    decision.event.revision
                ))?,
                vec![delta, tamper_delta],
                [staged.event_root],
            )?;
            publisher.append(batch)?
        };
        Ok(ReferenceEventReceipt {
            event_root: staged.event_root,
            event_object_digest: staged.event_object_digest,
            event_revision_digest: staged.event_revision_digest,
            authority_anchor,
            lineage_tamper_status: combined_tamper,
            prior_revision_encodings,
        })
    }

    /// Reads the event's current authoritative revision and a receipt for it, without writing.
    ///
    /// The revision is the one the ledger's current event object names: its `event_revision`
    /// delta at the current generation and payload, decoded from the spool and required to hash to
    /// the delta's witness. The receipt's anchor is the anchor of the batch that published it, and
    /// its lineage tamper status is recomputed from every revision the ledger published. A later
    /// consumer (alert preparation) cross-checks all of it against the ledger again; the receipt
    /// is never authority by itself.
    pub fn current_event_authority(
        &self,
        event_id: &EventId,
    ) -> Result<(EventHypothesis, ReferenceEventReceipt), ReferenceError> {
        let object_id = ObjectId::parse(format!("object:event:{}", event_id.as_str()))?;
        let current = self
            .ledger
            .current()
            .objects
            .get(&object_id)
            .ok_or(ContractError::NotFound)?;
        let (anchor, event_root, witness) = self
            .ledger
            .batches()
            .iter()
            .rev()
            .find_map(|batch| {
                batch
                    .deltas
                    .iter()
                    .find(|delta| {
                        delta.object_id == object_id
                            && delta.family == "event_revision"
                            && delta.new_generation == current.generation
                            && delta.payload_digest == current.payload_digest
                    })
                    .map(|delta| {
                        (
                            batch.new_anchor.clone(),
                            delta.payload_digest,
                            delta.witness_digest,
                        )
                    })
            })
            .ok_or(ContractError::SupersessionMismatch)?;
        let spool = self.publisher.spool();
        let manifest_bytes = spool
            .read(event_root)
            .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))?;
        let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)?;
        let event_object_digest = manifest
            .metadata_digest()
            .ok_or(ContractError::EvidenceRequired)?;
        let event_bytes = spool
            .read(event_object_digest)
            .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))?;
        let event = EventHypothesis::from_canonical_bytes(&event_bytes)?;
        let event_revision_digest = event.revision_digest();
        if witness != Some(event_revision_digest) || event.event_id != *event_id {
            return Err(ContractError::SupersessionMismatch.into());
        }
        let prior = self.prior_event_revisions(&object_id, event.revision)?;
        let lineage_tamper_status = fss_core::event::compute_sensor_tamper_status(
            prior.iter().chain(std::iter::once(&event)),
            None,
        );
        let receipt = ReferenceEventReceipt {
            event_root,
            event_object_digest,
            event_revision_digest,
            authority_anchor: anchor,
            lineage_tamper_status,
            prior_revision_encodings: prior
                .iter()
                .map(crate::alert::event_revision_encoding)
                .collect(),
        };
        Ok((event, receipt))
    }

    /// Every earlier revision of the event `object_id`, oldest first, read back from this
    /// deployment's spool through the `event_revision` deltas its ledger committed.
    fn prior_event_revisions(
        &self,
        object_id: &ObjectId,
        current_revision: u64,
    ) -> Result<Vec<EventHypothesis>, ReferenceError> {
        let spool = self.publisher.spool();
        let read = |digest: ContentDigest| {
            spool
                .read(digest)
                .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))
        };
        let mut prior = Vec::new();
        for batch in self.ledger.batches() {
            for delta in &batch.deltas {
                if delta.object_id == *object_id && delta.family == "event_revision" {
                    let manifest =
                        ObjectManifest::from_canonical_bytes(&read(delta.payload_digest)?)?;
                    let payload = manifest
                        .metadata_digest()
                        .or_else(|| manifest.children().first().copied())
                        .ok_or(ContractError::EvidenceRequired)?;
                    let revision = EventHypothesis::from_canonical_bytes(&read(payload)?)?;
                    if revision.revision < current_revision {
                        prior.push(revision);
                    }
                }
            }
        }
        prior.sort_by_key(|revision| revision.revision);
        prior.dedup_by_key(|revision| revision.revision);
        Ok(prior)
    }

    /// Stages the canonical encoding of `status` in the spool; its digest must be the status
    /// witness digest, or the publication fails closed.
    fn stage_tamper_status(
        &mut self,
        status: &fss_core::SensorTamperStatus,
    ) -> Result<(), ReferenceError> {
        let mut encoder = CanonicalEncoder::new();
        status.encode_canonical(&mut encoder);
        let staged = self.publisher.stage_object(&encoder.finish())?;
        if staged != status.canonical_digest() {
            return Err(ContractError::DigestMismatch.into());
        }
        Ok(())
    }

    fn stage_event_revision(
        &mut self,
        decision: &ReferencePolicyDecision,
    ) -> Result<StagedEventRevision, ReferenceError> {
        for model_receipt in &decision.event.model_receipts {
            self.publisher.verify_object(*model_receipt)?;
        }
        let event_bytes = decision.event.canonical_bytes();
        let event_object_digest = self.publisher.stage_object(&event_bytes)?;
        let mut revision_encoder = CanonicalEncoder::new();
        revision_encoder.text("fss.canonical.v1");
        revision_encoder.text("fss.event_hypothesis.v1");
        decision.event.encode_canonical(&mut revision_encoder);
        let event_revision_digest = self.publisher.stage_object(&revision_encoder.finish())?;
        let event_manifest = ObjectManifest::new(
            "event-revision",
            decision.event.model_receipts.iter().copied(),
            Some(event_object_digest),
        )?;
        let manifest_bytes = event_manifest.canonical_bytes();
        let event_root = self.publisher.stage_object(&manifest_bytes)?;
        Ok(StagedEventRevision {
            event_root,
            event_object_digest,
            event_revision_digest,
        })
    }

    /// Dispatches an alert durably through the deployment-owned simulated provider.
    pub fn dispatch_alert(
        &mut self,
        plan: &ReferenceAlertPlan,
        behavior: ReferenceProviderBehavior,
        committed_at: TimestampNs,
        outcome_at: TimestampNs,
        cx: &ReplayCx,
    ) -> Result<OperationReceipt, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_DISPATCH_ALERT,
            });
        }
        let receipt = crate::alert::execute_alert_dispatch(crate::alert::AlertDispatchOptions {
            plan,
            authority: &self.ledger,
            read_payload: |digest| {
                self.publisher
                    .spool()
                    .read(digest)
                    .map(|bytes| bytes.to_vec())
                    .map_err(|error| ReferenceError::from(LocalPublicationError::Spool(error)))
            },
            behavior,
            commit_at: committed_at,
            outcome_at,
            journal: &mut self.effects,
            provider: &mut self.alert_provider,
        })
        .map_err(|error| match error {
            // The composition layer owns the durable journal, so journal state-machine
            // verdicts surface wrapped in this layer's effect error.
            ReferenceError::Contract(contract_error) => ReferenceError::DurableEffect(Box::new(
                crate::durable_effect::DurableEffectError::Contract(contract_error),
            )),
            ReferenceError::StaleEventAuthority => ReferenceError::DurableEffect(Box::new(
                crate::durable_effect::DurableEffectError::Reference(
                    ReferenceError::StaleEventAuthority,
                ),
            )),
            other => other,
        })?;
        Ok(receipt)
    }

    /// Compiles a situation projection bound to this deployment's durable effect journal and ledger.
    pub fn compile_situation(
        &self,
        request: ReferenceSituationRequest<'_>,
        cx: &ReplayCx,
    ) -> Result<ReferenceSituation, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_COMPILE_SITUATION,
            });
        }
        compile_reference_situation_with_durable_journal(request, &self.effects, &self.ledger)
    }

    /// Seals a verified handoff capsule from a compiled reference situation.
    pub fn seal_handoff(
        &self,
        situation: &ReferenceSituation,
        handoff_id: HandoffId,
        created_at: TimestampNs,
        expires_at: TimestampNs,
        cx: &ReplayCx,
    ) -> Result<HandoffCapsule, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_SEAL_HANDOFF,
            });
        }
        seal_reference_handoff(situation, handoff_id, created_at, expires_at)
    }

    /// Returns the root filesystem path of this deployment.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the site lineage identifier.
    #[must_use]
    pub fn site_lineage(&self) -> &str {
        &self.site_lineage
    }

    /// Returns the capacity limits configured for this deployment.
    #[must_use]
    pub const fn limits(&self) -> &DeploymentLimits {
        &self.limits
    }

    /// Returns the read-only deployment layout descriptor.
    #[must_use]
    pub const fn layout_report(&self) -> &DeploymentLayout {
        &self.layout
    }

    /// Returns the publication recovery report observed on open.
    #[must_use]
    pub const fn recovery_report(&self) -> &LocalRecoveryReport {
        self.publisher.recovery_report()
    }

    /// Returns a reference to the durable authority ledger.
    #[must_use]
    pub const fn ledger(&self) -> &DurableReferenceLedger {
        &self.ledger
    }

    /// Returns a mutable reference to the durable authority ledger.
    ///
    /// Test-only and crate-internal: outside callers commit authority only through the guarded
    /// entry points (`append_batch`, `publish_event`, `publish_and_commit`); the in-crate tests use
    /// it to arm journal fault injection.
    #[cfg(test)]
    pub(crate) fn ledger_mut(&mut self) -> &mut DurableReferenceLedger {
        &mut self.ledger
    }

    /// Returns a reference to the local root publisher.
    #[must_use]
    pub const fn publisher(&self) -> &LocalRootPublisher {
        &self.publisher
    }

    /// Returns a mutable reference to the local root publisher.
    pub fn publisher_mut(&mut self) -> &mut LocalRootPublisher {
        &mut self.publisher
    }

    /// Returns a reference to the durable effect journal.
    #[must_use]
    pub const fn effects(&self) -> &DurableEffectJournal {
        &self.effects
    }

    /// Returns a mutable reference to the durable effect journal.
    pub fn effects_mut(&mut self) -> &mut DurableEffectJournal {
        &mut self.effects
    }

    /// Returns the durable effect journal mutably together with the authority ledger it must be
    /// checked against, so an alert is prepared against this deployment's own authority (for
    /// example through [`DurableEffectJournal::prepare_alert`]).
    pub fn effects_and_ledger(&mut self) -> (&mut DurableEffectJournal, &DurableReferenceLedger) {
        (&mut self.effects, &self.ledger)
    }

    /// Returns the durable effect journal mutably with the authority ledger and the local root
    /// publisher whose verified spool holds the event revisions, so an alert dispatch (for
    /// example [`crate::webhook::WebhookAttempt`]) revalidates against this deployment's own
    /// authority and reads payloads only through verified custody.
    pub fn effect_dispatch_parts(
        &mut self,
    ) -> (
        &mut DurableEffectJournal,
        &DurableReferenceLedger,
        &LocalRootPublisher,
    ) {
        (&mut self.effects, &self.ledger, &self.publisher)
    }

    /// Returns a reference to the deployment-owned simulated alert provider.
    #[must_use]
    pub const fn alert_provider(&self) -> &ReferenceAlertProvider {
        &self.alert_provider
    }

    /// Returns a mutable reference to the deployment-owned simulated alert provider.
    pub fn alert_provider_mut(&mut self) -> &mut ReferenceAlertProvider {
        &mut self.alert_provider
    }

    /// Current canonical authority anchor.
    #[must_use]
    pub fn current_anchor(&self) -> &LedgerAnchor {
        &self.ledger.current().anchor
    }
}
