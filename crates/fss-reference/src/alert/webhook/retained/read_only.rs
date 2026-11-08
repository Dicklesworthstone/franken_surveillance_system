#![forbid(unsafe_code)]
//! Strict inspection of one retained observation without opening a deployment mutation owner.

use std::io;
use std::path::{Component, Path, PathBuf};

use fss_core::durable::DurableFormat;
use fss_core::{CanonicalEncode, ContentDigest, ContextAuthority, OperationId, Plane, PrincipalId};
use fss_ledger::{
    HostJournalReadIo, JournalFileMetadata, JournalReadIo, LedgerInspection,
    inspect_durable_with_io,
};
use fss_object::{
    ObjectManifest, SPOOL_HOLDS_DIR, SPOOL_OBJECT_FORMAT_VERSION, SPOOL_OBJECT_HEADER_LEN,
    SPOOL_OBJECT_MAGIC, SPOOL_OBJECTS_DIR,
};
use fss_publication::{
    LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LOCAL_TOMBSTONES_DIR, MAX_ROOT_RECORD_BYTES,
    ROOT_INDETERMINATE_SUFFIX, ROOT_REACHABILITY_FAMILY, ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX,
    SlotName, TOMBSTONE_RECORD_SUFFIX, root_reachability_batch_id, root_reachability_object_id,
    root_record_bytes,
};

use super::{
    CAP_ALERT_STATUS, MAX_CONTROL_JOURNAL_BYTES, MAX_WEBHOOK_MANIFEST_BYTES,
    MAX_WEBHOOK_OBSERVATION_BYTES, RetainedWebhookEvidence, STAGE_AUTHORITY, STAGE_HISTORY,
    STAGE_OBSERVATION, STAGE_RETAINED, WEBHOOK_CUSTODY_BYTES, WEBHOOK_CUSTODY_STORAGE_OPERATIONS,
    WebhookRetentionError, checkpoint, codec, slot, verify_history_binding, wire,
};
use crate::doctor::MAX_LAYOUT_BYTES;
use crate::reference_deployment::{
    DEPLOYMENT_LAYOUT_FILENAME, DeploymentLayout, RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER,
    RELATIVE_PATH_OBJECTS,
};
use crate::{ReplayAdmission, ReplayCx};

/// Inspect exactly one wire observation without locks, writes, fsync, recovery, or network I/O.
///
/// The complete bounded journals, selected root record, two spool objects and verification
/// holds are read through the current owner. All observed files and absences are checked again
/// before returning. An incomplete journal tail, detected change, retraction or missing custody
/// is refused; this inspection never repairs it or advances a `Committed` operation. These are
/// bounded observations through JournalReadIo, not an exclusive or atomic filesystem snapshot.
pub fn read_retained_webhook_evidence_from_root(
    root: &Path,
    operation_id: &OperationId,
    authority: &ContextAuthority,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<Option<RetainedWebhookEvidence>, WebhookRetentionError> {
    read_retained_webhook_evidence_from_root_with_io(
        &HostJournalReadIo,
        root,
        operation_id,
        authority,
        cx,
    )
}

/// The strict root inspector through an explicit read-only filesystem capability.
///
/// Journal input is capped at 64 MiB each, wire input at 32 KiB, and actual cumulative reads
/// consume the supplied context's finite byte/storage envelope. Every metadata and file-read
/// call consumes one storage operation. A deadline-bearing context
/// additionally requires live `ReplayCx::with_admission` checks around every I/O boundary.
pub fn read_retained_webhook_evidence_from_root_with_io(
    io: &dyn JournalReadIo,
    root: &Path,
    operation_id: &OperationId,
    authority: &ContextAuthority,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<Option<RetainedWebhookEvidence>, WebhookRetentionError> {
    authority.validate()?;
    checkpoint(cx, STAGE_AUTHORITY)?;
    if !authority.has_capability(CAP_ALERT_STATUS)
        || authority.cancellation_reason.is_some()
        || (authority.deadline.is_some() && !cx.has_owner_admission())
        || cx.root_dir() != root
        || cx.io_authority().principal() != authority.principal
        || PrincipalId::parse(&authority.principal).is_err()
        || !root.is_absolute()
        || root
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(WebhookRetentionError::Unauthorized);
    }
    if authority.budgets.bytes < WEBHOOK_CUSTODY_BYTES
        || authority.budgets.storage_operations < WEBHOOK_CUSTODY_STORAGE_OPERATIONS
    {
        return Err(WebhookRetentionError::Budget);
    }
    let mut reader = Reader {
        io,
        root,
        cx,
        bytes_left: authority.budgets.bytes,
        operations_left: authority.budgets.storage_operations,
        files: Vec::new(),
    };
    reader.directory(root)?;
    let layout_path = root.join(DEPLOYMENT_LAYOUT_FILENAME);
    let layout_bytes = reader.required(&layout_path, MAX_LAYOUT_BYTES)?;
    let layout = DeploymentLayout::parse_canonical_text(
        std::str::from_utf8(&layout_bytes).map_err(|_| WebhookRetentionError::Invalid)?,
    )?;
    if layout.ledger_relpath != RELATIVE_PATH_LEDGER
        || layout.effects_relpath != RELATIVE_PATH_EFFECTS
        || layout.objects_relpath != RELATIVE_PATH_OBJECTS
        || crate::reference_deployment::validate_site_lineage(&layout.site_lineage).is_err()
        || authority.anchor_universe != ContentDigest::sha256(layout.site_lineage.as_bytes())
    {
        return Err(WebhookRetentionError::Unauthorized);
    }
    let maximum =
        usize::try_from(MAX_CONTROL_JOURNAL_BYTES).map_err(|_| WebhookRetentionError::Budget)?;
    let ledger_path = root.join(&layout.ledger_relpath);
    let effects_path = root.join(&layout.effects_relpath);
    let ledger_bytes = reader.required(&ledger_path, maximum)?;
    let effects_bytes = reader.required(&effects_path, maximum)?;
    // The doctor-oriented inspectors alone can classify committed corruption as a foreign
    // tail. Strict framing validation must precede semantic replay, never discard that tail.
    let ledger_report =
        fss_ledger::recover_bytes(&ledger_bytes).map_err(|_| WebhookRetentionError::Custody)?;
    let effect_report =
        fss_ledger::recover_bytes(&effects_bytes).map_err(|_| WebhookRetentionError::Custody)?;
    if ledger_report.incomplete_tail().is_some() || effect_report.incomplete_tail().is_some() {
        return Err(WebhookRetentionError::Custody);
    }
    checkpoint(cx, STAGE_HISTORY)?;
    let ledger = inspect_durable_with_io(
        &SnapshotIo {
            path: &ledger_path,
            bytes: &ledger_bytes,
        },
        &ledger_path,
        layout.site_lineage.clone(),
        maximum,
    )
    .map_err(|_| WebhookRetentionError::Custody)?;
    let effects = crate::durable_effect::replay_records(effect_report.records())?;
    checkpoint(cx, STAGE_HISTORY)?;
    let operation = effects
        .operation(operation_id)
        .ok_or(WebhookRetentionError::NotAlert)?;
    if operation.intent.effect_class != "alert.dispatch" {
        return Err(WebhookRetentionError::NotAlert);
    }
    let prepared = effects.prepared_record(operation_id)?;
    if prepared.intent != operation.intent {
        return Err(WebhookRetentionError::Invalid);
    }
    let slot = slot(&layout.site_lineage, &prepared)?;
    let publication = root.join(&layout.objects_relpath);
    let root_path = publication
        .join(LOCAL_ROOTS_DIR)
        .join(format!("{slot}{ROOT_RECORD_SUFFIX}"));
    let root_bytes = reader.optional(&root_path, MAX_ROOT_RECORD_BYTES as usize)?;
    for suffix in [ROOT_TEMP_SUFFIX, ROOT_INDETERMINATE_SUFFIX] {
        let marker = root_path.with_file_name(format!("{slot}{ROOT_RECORD_SUFFIX}{suffix}"));
        reader.absent(&marker)?;
    }
    let object = root_reachability_object_id(&slot).map_err(|_| WebhookRetentionError::Invalid)?;
    let Some(revision) = ledger.snapshot.objects.get(&object) else {
        if root_bytes.is_some() {
            return Err(WebhookRetentionError::Custody);
        }
        reader.finish()?;
        return Ok(None);
    };
    if revision.family != ROOT_REACHABILITY_FAMILY
        || revision.plane != Plane::Authority
        || revision.generation != 1
    {
        return Err(WebhookRetentionError::Conflict);
    }
    let root_digest = revision.payload_digest;
    let expected_root =
        root_record_bytes(&slot, root_digest, 1).map_err(|_| WebhookRetentionError::Invalid)?;
    if root_bytes.as_deref() != Some(expected_root.as_slice()) {
        return Err(WebhookRetentionError::Custody);
    }
    let manifest_bytes = reader.object(&publication, root_digest, MAX_WEBHOOK_MANIFEST_BYTES)?;
    let manifest = ObjectManifest::from_canonical_bytes(&manifest_bytes)
        .map_err(|_| WebhookRetentionError::Invalid)?;
    if manifest.root() != root_digest
        || manifest.kind() != slot.as_str()
        || manifest.children().len() != 1
        || manifest.metadata_digest().is_some()
        || manifest.canonical_bytes() != manifest_bytes
    {
        return Err(WebhookRetentionError::Invalid);
    }
    verify_linkage(&ledger, &slot, &manifest)?;
    let digest = manifest.children()[0];
    let bytes = reader.object(&publication, digest, MAX_WEBHOOK_OBSERVATION_BYTES)?;
    let observation = codec::decode(&bytes)?;
    if observation.intent != prepared.intent || observation.digest() != digest {
        return Err(WebhookRetentionError::Invalid);
    }
    let journal_observation_recorded =
        verify_history_binding(effect_report.records(), &prepared, &observation)?;
    let retained = RetainedWebhookEvidence {
        observation,
        digest,
        root: root_digest,
        slot,
        prepared: prepared.prepared_record_digest(),
        journal_observation_recorded,
    };
    reader.finish()?;
    Ok(Some(retained))
}

fn verify_linkage(
    ledger: &LedgerInspection,
    slot: &SlotName,
    manifest: &ObjectManifest,
) -> Result<(), WebhookRetentionError> {
    let object = root_reachability_object_id(slot).map_err(|_| WebhookRetentionError::Invalid)?;
    let batch_id = root_reachability_batch_id(slot).map_err(|_| WebhookRetentionError::Invalid)?;
    if !ledger.batches.iter().any(|batch| {
        batch.batch_id == batch_id
            && batch.children == manifest.children()
            && batch.deltas.len() == 1
            && batch.deltas.iter().any(|delta| {
                delta.object_id == object
                    && delta.family == ROOT_REACHABILITY_FAMILY
                    && delta.payload_digest == manifest.root()
                    && delta.plane == Plane::Authority
                    && delta.prior_generation.is_none()
                    && delta.new_generation == 1
                    && delta.witness_digest.is_none()
                    && delta.operation_id.is_none()
            })
    }) {
        return Err(WebhookRetentionError::Custody);
    }
    Ok(())
}

struct FileSnapshot {
    path: PathBuf,
    maximum: usize,
    bytes: Option<Vec<u8>>,
    absence_only: bool,
}

struct Reader<'a, G: ReplayAdmission> {
    io: &'a dyn JournalReadIo,
    root: &'a Path,
    cx: &'a ReplayCx<G>,
    bytes_left: u64,
    operations_left: u64,
    files: Vec<FileSnapshot>,
}

impl<G: ReplayAdmission> Reader<'_, G> {
    fn charge_operation(&mut self) -> Result<(), WebhookRetentionError> {
        self.operations_left = self
            .operations_left
            .checked_sub(1)
            .ok_or(WebhookRetentionError::Budget)?;
        Ok(())
    }

    fn metadata(
        &mut self,
        path: &Path,
    ) -> Result<Option<JournalFileMetadata>, WebhookRetentionError> {
        self.charge_operation()?;
        checkpoint(self.cx, STAGE_OBSERVATION)?;
        let observed = self.io.symlink_metadata(path);
        checkpoint(self.cx, STAGE_OBSERVATION)?;
        match observed {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(WebhookRetentionError::Custody),
        }
    }

    fn directory(&mut self, path: &Path) -> Result<(), WebhookRetentionError> {
        let metadata = self.metadata(path)?.ok_or(WebhookRetentionError::Custody)?;
        if metadata.is_file || metadata.is_symlink {
            return Err(WebhookRetentionError::Custody);
        }
        Ok(())
    }

    fn scope(&mut self, path: &Path) -> Result<(), WebhookRetentionError> {
        // Refuse observed symlink ancestors in the exact layout-derived scope. JournalReadIo
        // owns the actual read capability; path metadata is not an atomic no-follow primitive.
        let relative = path
            .strip_prefix(self.root)
            .map_err(|_| WebhookRetentionError::Unauthorized)?;
        let mut parent = self.root.to_path_buf();
        self.directory(&parent)?;
        if let Some(relative_parent) = relative.parent() {
            for part in relative_parent.components() {
                let Component::Normal(part) = part else {
                    return Err(WebhookRetentionError::Unauthorized);
                };
                parent.push(part);
                self.directory(&parent)?;
            }
        }
        Ok(())
    }

    fn check_absent(&mut self, path: &Path) -> Result<(), WebhookRetentionError> {
        self.scope(path)?;
        if self.metadata(path)?.is_some() {
            return Err(WebhookRetentionError::Custody);
        }
        Ok(())
    }

    fn absent(&mut self, path: &Path) -> Result<(), WebhookRetentionError> {
        self.check_absent(path)?;
        self.files.push(FileSnapshot {
            path: path.to_path_buf(),
            maximum: 0,
            bytes: None,
            absence_only: true,
        });
        Ok(())
    }

    fn read(
        &mut self,
        path: &Path,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, WebhookRetentionError> {
        self.scope(path)?;
        let Some(metadata) = self.metadata(path)? else {
            return Ok(None);
        };
        if !metadata.is_file || metadata.is_symlink {
            return Err(WebhookRetentionError::Custody);
        }
        let length = usize::try_from(metadata.len).map_err(|_| WebhookRetentionError::Budget)?;
        if length > maximum {
            return Err(WebhookRetentionError::Budget);
        }
        let bound = length.checked_add(1).ok_or(WebhookRetentionError::Budget)?;
        self.bytes_left = self
            .bytes_left
            .checked_sub(bound as u64)
            .ok_or(WebhookRetentionError::Budget)?;
        self.charge_operation()?;
        checkpoint(self.cx, STAGE_OBSERVATION)?;
        let bytes = self
            .io
            .read_bounded(path, bound)
            .map_err(|_| WebhookRetentionError::Custody)?;
        checkpoint(self.cx, STAGE_OBSERVATION)?;
        if bytes.len() != length {
            return Err(WebhookRetentionError::Custody);
        }
        Ok(Some(bytes))
    }

    fn optional(
        &mut self,
        path: &Path,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, WebhookRetentionError> {
        let bytes = self.read(path, maximum)?;
        self.files.push(FileSnapshot {
            path: path.to_path_buf(),
            maximum,
            bytes: bytes.clone(),
            absence_only: false,
        });
        Ok(bytes)
    }

    fn required(&mut self, path: &Path, maximum: usize) -> Result<Vec<u8>, WebhookRetentionError> {
        self.optional(path, maximum)?
            .ok_or(WebhookRetentionError::Custody)
    }

    fn object(
        &mut self,
        publication: &Path,
        digest: ContentDigest,
        maximum: usize,
    ) -> Result<Vec<u8>, WebhookRetentionError> {
        let stem = wire::hex(digest);
        // Publication names include the algorithm; spool object and hold names are hex only.
        let publication_stem = digest.to_text().replacen(':', "-", 1);
        for suffix in ["", ROOT_TEMP_SUFFIX, ROOT_INDETERMINATE_SUFFIX] {
            let tombstone = publication.join(LOCAL_TOMBSTONES_DIR).join(format!(
                "{publication_stem}{TOMBSTONE_RECORD_SUFFIX}{suffix}"
            ));
            self.absent(&tombstone)?;
        }
        let spool = publication.join(LOCAL_SPOOL_DIR);
        let hold = spool.join(SPOOL_HOLDS_DIR).join(&stem);
        if !self.required(&hold, 0)?.is_empty() {
            return Err(WebhookRetentionError::Custody);
        }
        let path = spool.join(SPOOL_OBJECTS_DIR).join(stem);
        let bound = maximum
            .checked_add(SPOOL_OBJECT_HEADER_LEN)
            .ok_or(WebhookRetentionError::Budget)?;
        let raw = self.required(&path, bound)?;
        let format =
            DurableFormat::spool_object(&SPOOL_OBJECT_MAGIC, SPOOL_OBJECT_FORMAT_VERSION, maximum);
        let decoded = format
            .decode(&raw)
            .map_err(|_| WebhookRetentionError::Custody)?;
        if decoded.checksum() != digest {
            return Err(WebhookRetentionError::Custody);
        }
        Ok(decoded.payload().to_vec())
    }

    fn finish(mut self) -> Result<(), WebhookRetentionError> {
        let files = std::mem::take(&mut self.files);
        for file in files {
            if file.absence_only {
                self.check_absent(&file.path)?;
            } else if self.read(&file.path, file.maximum)? != file.bytes {
                return Err(WebhookRetentionError::Custody);
            }
        }
        checkpoint(self.cx, STAGE_RETAINED)
    }
}

/// Existing typed replay sees a fixed snapshot rather than a second uncontrolled file read.
struct SnapshotIo<'a> {
    path: &'a Path,
    bytes: &'a [u8],
}

impl JournalReadIo for SnapshotIo<'_> {
    fn symlink_metadata(&self, path: &Path) -> io::Result<JournalFileMetadata> {
        if path != self.path {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        Ok(JournalFileMetadata {
            is_file: true,
            is_symlink: false,
            len: self.bytes.len() as u64,
        })
    }
    fn read_bounded(&self, path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
        if path != self.path {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        Ok(self.bytes[..maximum.min(self.bytes.len())].to_vec())
    }
}
