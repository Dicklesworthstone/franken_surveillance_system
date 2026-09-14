#![forbid(unsafe_code)]
//! Deterministic reference deployment composition.
//!
//! Lifts the composition of [`DurableReferenceLedger`], [`LocalRootPublisher`] (with its owned
//! [`StagingSpool`](fss_object::StagingSpool)), and [`DurableEffectJournal`] into one canonical library
//! type defining a deployment root on disk.

use std::fs::{self, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CaptureInterval, ContentDigest, ContractError,
    EventId, EvidenceDelta, EvidenceDeltaBatch, HandoffCapsule, HandoffId, LedgerAnchor,
    OperationReceipt, TimestampNs,
};
use fss_ledger::{
    DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, JournalError, RepairReceipt,
    doctor, recover_bytes,
};
use fss_object::{InMemoryObjectStore, ObjectManifest, SpoolLimits};
use fss_publication::{
    AuthorityPublisher, LedgeredRootPublisher, LocalPublicationError, LocalPublicationLimits,
    LocalPublicationReceipt, LocalRecoveryReport, LocalRootPublisher, PublishCancellation,
    PublishCutPoint, RootLedgerReceipt, RootLedgerReconciliation, SlotName,
};

use crate::adapter_replay::ReplayCx;
use crate::alert::{ReferenceAlertPlan, ReferenceAlertProvider, ReferenceProviderBehavior};
use crate::durable_effect::{DurableEffectError, DurableEffectJournal};
use crate::error::ReferenceError;
use crate::policy::{
    ReferenceEventReceipt, ReferenceModelObservation, ReferencePolicyDecision,
    evaluate_unknown_presence, publish_reference_event,
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

/// Known ledger delta families table.
pub const KNOWN_LEDGER_DELTA_FAMILIES: &[&str] = &[
    FAMILY_SENSOR_CAPSULE,
    FAMILY_EVENT_REVISION,
    FAMILY_ALERT_EFFECT_OUTCOME,
    FAMILY_FILE_IMPORT_MANIFEST,
    FAMILY_ACQUISITION_TRANSITION,
    FAMILY_DECODE_RECEIPT,
    FAMILY_MODEL_INVOCATION_RECEIPT,
    FAMILY_EXECUTOR_MODEL_RESULT,
    FAMILY_TWIN_LOCALIZATION_RECEIPT,
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
];

/// Validates that `site_lineage` meets token grammar constraints.
///
/// Refuses empty strings, whitespace, control characters, and non-ASCII characters.
pub fn validate_site_lineage(lineage: &str) -> Result<(), ReferenceError> {
    if lineage.is_empty() {
        return Err(ReferenceError::InvalidSpec("deployment site_lineage is empty"));
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

fn find_structurally_valid_record(
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
    /// Maximum entries listed from directory on open (default: 4,096).
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
    /// Standard 4,096 directory entries scan maximum.
    pub const STANDARD_SCAN_MAX_OBJECTS: usize = 4096;

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
        let spool_scan = self.spool_max_objects.max(self.scan_max_objects);
        LocalPublicationLimits::new(
            self.max_roots,
            self.manifest_children_max,
            self.max_tombstones,
            self.scan_max_objects.max(self.max_roots).max(self.max_tombstones),
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
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(ReferenceError::InvalidSpec(
                    "layout line must use '=' separator",
                ));
            };
            let key = key.trim();
            let value = value.trim();

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
                        return Err(ReferenceError::InvalidSpec("invalid layout objects relpath"));
                    }
                    objects = Some(value.to_owned());
                }
                "effects" => {
                    if effects.is_some() {
                        return Err(ReferenceError::InvalidSpec("duplicate layout key: effects"));
                    }
                    if value != RELATIVE_PATH_EFFECTS {
                        return Err(ReferenceError::InvalidSpec("invalid layout effects relpath"));
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

        Ok(Self {
            schema,
            format_version: version,
            site_lineage,
            ledger_relpath: ledger,
            objects_relpath: objects,
            effects_relpath: effects,
            limits_digest,
        })
    }
}

fn write_layout_atomic(root: &Path, layout: &DeploymentLayout) -> Result<(), ReferenceError> {
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
    fs::rename(&temp_path, &layout_path)?;
    let dir = fs::File::open(root)?;
    dir.sync_all()?;
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

/// Cancellation probe bridging [`ReplayCx`] to [`PublishCancellation`].
#[derive(Debug)]
pub struct ReplayCancellationBridge<'a>(pub &'a ReplayCx);

impl PublishCancellation for ReplayCancellationBridge<'_> {
    fn cancel_requested(&self, _point: PublishCutPoint) -> bool {
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
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_DEPLOYMENT_OPEN,
            });
        }

        validate_site_lineage(site_lineage)?;

        let root_buf = root.to_path_buf();
        if root.exists() && !root.is_dir() {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }

        let ledger_path = root.join(RELATIVE_PATH_LEDGER);
        let objects_dir = root.join(RELATIVE_PATH_OBJECTS);
        let effects_path = root.join(RELATIVE_PATH_EFFECTS);
        let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);

        if !root.exists() {
            fs::create_dir_all(root)?;
        }
        fs::create_dir_all(&objects_dir)?;

        // 1. Open local root publisher first: exclusive lock prevents concurrent access.
        // A second open refused here never touches or mutates either journal.
        let pub_limits = limits.to_publication_limits();
        let publisher = match LocalRootPublisher::open(&objects_dir, pub_limits) {
            Ok(p) => p,
            Err(LocalPublicationError::Locked { path }) => {
                return Err(ReferenceError::DeploymentLocked { path });
            }
            Err(other) => return Err(ReferenceError::LocalPublication(Box::new(other))),
        };

        // 2. Initialize or verify layout descriptor atomically.
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("LAYOUT.tmp.") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        let limits_digest = limits.canonical_digest()?;
        let layout = if layout_path.exists() {
            let content = fs::read_to_string(&layout_path)?;
            let parsed = DeploymentLayout::parse_canonical_text(&content)?;
            if parsed.site_lineage != site_lineage {
                return Err(ReferenceError::InvalidSpec(
                    "deployment site_lineage mismatch",
                ));
            }
            if parsed.limits_digest != limits_digest {
                return Err(ReferenceError::InvalidSpec(
                    "deployment limits_digest mismatch",
                ));
            }
            parsed
        } else {
            if !is_skeleton_or_empty(root)? {
                return Err(ReferenceError::NotADeployment { path: root_buf });
            }
            let new_layout = DeploymentLayout::new(site_lineage, limits_digest);
            write_layout_atomic(root, &new_layout)?;
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
        let objects_dir = root.join(RELATIVE_PATH_OBJECTS);
        fs::create_dir_all(&objects_dir)?;
        let lock_path = objects_dir.join("LOCK");
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
        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().starts_with("LAYOUT.tmp.") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }

        // Verify layout descriptor exists and is valid; open_for_recovery never creates LAYOUT.
        if layout_path.exists() {
            let content = fs::read_to_string(&layout_path)?;
            let _layout = DeploymentLayout::parse_canonical_text(&content)?;
        } else if !is_skeleton_or_empty(root)? {
            return Err(ReferenceError::NotADeployment { path: root_buf });
        }

        match action {
            RecoveryAction::TruncateIncompleteLedgerTail => {
                let target_path = root.join(RELATIVE_PATH_LEDGER);
                if !target_path.exists() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let bytes = fs::read(&target_path)?;
                let recovery = recover_bytes(&bytes)?;
                if recovery.incomplete_tail().is_some() {
                    let total_len = bytes.len() as u64;
                    let committed_len = recovery.committed_len();
                    let truncated_bytes = total_len.saturating_sub(committed_len);
                    let last_root_before = recovery.last_root();
                    let file = OpenOptions::new().write(true).open(&target_path)?;
                    file.set_len(committed_len)?;
                    file.sync_all()?;
                    let after_bytes = fs::read(&target_path)?;
                    let after_recovery = recover_bytes(&after_bytes)?;
                    let last_root_after = after_recovery.last_root();
                    Ok(RecoveryReceipt::TruncatedLedgerTail {
                        path: target_path,
                        committed_len,
                        truncated_bytes,
                        last_root_before,
                        last_root_after,
                    })
                } else {
                    Err(ReferenceError::NoIncompleteTail { path: target_path })
                }
            }
            RecoveryAction::TruncateIncompleteEffectTail => {
                let target_path = root.join(RELATIVE_PATH_EFFECTS);
                if !target_path.exists() {
                    return Err(ReferenceError::NoIncompleteTail { path: target_path });
                }
                let bytes = fs::read(&target_path)?;
                let recovery = recover_bytes(&bytes)?;
                if recovery.incomplete_tail().is_some() {
                    let total_len = bytes.len() as u64;
                    let committed_len = recovery.committed_len();
                    let truncated_bytes = total_len.saturating_sub(committed_len);
                    let last_root_before = recovery.last_root();
                    let file = OpenOptions::new().write(true).open(&target_path)?;
                    file.set_len(committed_len)?;
                    file.sync_all()?;
                    let after_bytes = fs::read(&target_path)?;
                    let after_recovery = recover_bytes(&after_bytes)?;
                    let last_root_after = after_recovery.last_root();
                    Ok(RecoveryReceipt::TruncatedEffectTail {
                        path: target_path,
                        committed_len,
                        truncated_bytes,
                        last_root_before,
                        last_root_after,
                    })
                } else {
                    Err(ReferenceError::NoIncompleteTail { path: target_path })
                }
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

    /// Stages child objects and manifest body, then publishes root-last with cooperative cancellation.
    ///
    /// This is a stage-only local root publication: it bypasses the canonical ledger and surfaces
    /// in [`ReferenceDeployment::reconcile`] as an uncommitted or orphaned root.
    pub fn stage_and_publish(
        &mut self,
        slot: &SlotName,
        objects: &[&[u8]],
        cx: &ReplayCx,
    ) -> Result<LocalPublicationReceipt, ReferenceError> {
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

        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_STAGE_MANIFEST,
            });
        }

        let manifest = ObjectManifest::new(slot.as_str(), child_digests, None)?;

        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_PUBLISH_ROOT,
            });
        }

        let bridge = ReplayCancellationBridge(cx);
        let receipt = self
            .publisher
            .publish_cancellable(slot, &manifest, &bridge)?;
        Ok(receipt)
    }

    /// Publishes a manifest into `slot` root-last and commits its reachability to the canonical ledger.
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

        let mut ledgered = LedgeredRootPublisher::new(&mut self.publisher, &mut self.ledger);
        let receipt = ledgered.publish_and_commit(slot, manifest, validity)?;
        Ok(receipt)
    }

    /// Prepares and commits an authority batch to the canonical ledger, verifying child custody.
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

        if deltas.len() > self.limits.batch_entries_max {
            return Err(ReferenceError::CapacityExceeded {
                limit: "batch_deltas_max",
                maximum: self.limits.batch_entries_max as u64,
                actual: deltas.len() as u64,
            });
        }
        if children.len() > self.limits.batch_entries_max {
            return Err(ReferenceError::CapacityExceeded {
                limit: "batch_children_max",
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

        for child in &children {
            let _ = self.publisher.verify_object(*child);
        }
        for delta in &deltas {
            let _ = self.publisher.verify_object(delta.payload_digest);
            if let Some(witness) = delta.witness_digest {
                let _ = self.publisher.verify_object(witness);
            }
        }

        let mut auth = AuthorityPublisher::new(self.publisher.spool(), &mut self.ledger);
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
        objects: &mut InMemoryObjectStore,
        cx: &ReplayCx,
    ) -> Result<ReferenceEventReceipt, ReferenceError> {
        if cx.is_cancelled() {
            cx.drain_and_finalize();
            return Err(ReferenceError::CancellationRequested {
                stage: STAGE_PUBLISH_EVENT,
            });
        }
        let event_bytes = decision.event.canonical_bytes();
        let _ = self.publisher.stage_object(&event_bytes)?;
        for model_receipt in &decision.event.model_receipts {
            let bytes = objects.read_verified(*model_receipt)?;
            let _ = self.publisher.stage_object(bytes)?;
        }
        let mut revision_encoder = CanonicalEncoder::new();
        revision_encoder.text("fss.canonical.v1");
        revision_encoder.text("fss.event_hypothesis.v1");
        decision.event.encode_canonical(&mut revision_encoder);
        let revision_bytes = revision_encoder.finish();
        let _ = self.publisher.stage_object(&revision_bytes)?;

        publish_reference_event(decision, objects, &mut self.ledger)
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
        let receipt = self.effects.dispatch_alert(
            plan,
            &self.ledger,
            behavior,
            committed_at,
            outcome_at,
            &mut self.alert_provider,
        )?;
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
    pub fn ledger_mut(&mut self) -> &mut DurableReferenceLedger {
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
