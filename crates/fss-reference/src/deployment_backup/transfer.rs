#![forbid(unsafe_code)]
//! Capability-bound copy and root-last, permanently effect-fenced restoration.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::SpoolIo;
use fss_publication::{AuthorityPublisher, LocalRootPublisher};

use super::io::{PinnedSpoolIo, ReadIo, WriteTree, directory, fresh_path, source_locks};
use super::manifest::{BackupManifest, RestoreFence};
use super::snapshot::{DIRECTORIES, PAYLOAD_GUARD, SnapshotKind, snapshot};
use super::{
    BACKUP_MANIFEST_FILENAME, BACKUP_PAYLOAD_DIRECTORY, BackupAccess, BackupAuthority, BackupError,
    BackupLimits, BackupReceipt, DeploymentLimits, FAMILY_RESTORE_FENCE, RESTORE_FENCE_OBJECT_ID,
    RESTORE_INCOMPLETE_FILENAME, ReplayCx, RestoreReceipt, Result, STAGE_BACKUP_COPY,
    STAGE_BACKUP_PUBLISH, STAGE_RESTORE_ACTIVATE, STAGE_RESTORE_FENCED, STAGE_RESTORE_RESERVED,
    authorize,
};

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<()> {
    cx.checkpoint(stage).map_err(|_| BackupError::Cancelled)
}

/// Preview an exact source snapshot under existing deployment/publisher locks. No source open,
/// repair, effect reconciliation, clock read or destination creation occurs.
pub fn prepare_backup(
    source: &Path,
    deployment_limits: DeploymentLimits,
    limits: BackupLimits,
    authority: &dyn BackupAuthority,
    cx: &ReplayCx,
) -> Result<BackupManifest> {
    limits.validate()?;
    let gate = || authorize(authority, BackupAccess::ReadDeployment { source }, cx);
    gate()?;
    let root = directory(source)?;
    let _locks = source_locks(&root, cx, &gate)?;
    let io = ReadIo::new(cx, &gate, limits);
    snapshot(&root, deployment_limits, limits, &io, SnapshotKind::Source)
}

fn create_tree(writer: &mut WriteTree, root: &Path, gate: &dyn Fn() -> Result<()>) -> Result<()> {
    for relative in DIRECTORIES {
        writer.create_directory(&root.join(relative), gate)?;
    }
    Ok(())
}

fn copy_files(
    source: &Path,
    destination: &Path,
    manifest: &BackupManifest,
    omit_layout: bool,
    io: &ReadIo<'_>,
    writer: &WriteTree,
    gate: &dyn Fn() -> Result<()>,
    cx: &ReplayCx,
) -> Result<()> {
    for file in manifest.files() {
        if omit_layout && file.relative_path() == "LAYOUT" {
            continue;
        }
        checkpoint(cx, STAGE_BACKUP_COPY)?;
        gate()?;
        writer.check()?;
        let bytes = io.read_exact(&source.join(file.relative_path()), file.byte_len())?;
        if bytes.len() as u64 != file.byte_len() || ContentDigest::sha256(&bytes) != file.digest() {
            return Err(BackupError::Changed);
        }
        let mut opened = writer.write_new(&destination.join(file.relative_path()), &bytes, gate)?;
        let copied = io.read_owned(&mut opened, file.byte_len())?;
        writer.check()?;
        if copied != bytes {
            return Err(BackupError::Changed);
        }
    }
    Ok(())
}

/// Copy exactly an independently approved preview into a fresh private directory bundle.
/// A changed source or revoked original-read/destination grant fails closed. MANIFEST is last.
pub fn create_backup(
    source: &Path,
    bundle: &Path,
    expected_manifest: ContentDigest,
    deployment_limits: DeploymentLimits,
    limits: BackupLimits,
    authority: &dyn BackupAuthority,
    cx: &ReplayCx,
) -> Result<BackupReceipt> {
    limits.validate()?;
    let gate = || {
        authorize(authority, BackupAccess::ReadDeployment { source }, cx)?;
        authorize(
            authority,
            BackupAccess::WriteBundle {
                source,
                bundle,
                manifest: expected_manifest,
            },
            cx,
        )
    };
    gate()?;
    let source_root = directory(source)?;
    let bundle_root = fresh_path(bundle, &[&source_root])?;
    let _locks = source_locks(&source_root, cx, &gate)?;
    let io = ReadIo::new(cx, &gate, limits);
    let manifest = snapshot(
        &source_root,
        deployment_limits,
        limits,
        &io,
        SnapshotKind::Source,
    )?;
    if manifest.digest() != expected_manifest {
        return Err(BackupError::Changed);
    }
    let manifest_bytes = manifest.to_bytes();
    if manifest_bytes.len() > limits.max_manifest_bytes {
        return Err(BackupError::Limit("manifest_bytes"));
    }
    gate()?;
    let mut writer = WriteTree::reserve(&bundle_root, &gate)?;
    let payload = bundle_root.join(BACKUP_PAYLOAD_DIRECTORY);
    writer.create_directory(&payload, &gate)?;
    // Permanent profile-owned guard: a bundle's historical effect journal can never be opened
    // as a live deployment, even though its exact source LAYOUT is retained for restoration.
    writer.write_new(
        &payload.join(RESTORE_INCOMPLETE_FILENAME),
        PAYLOAD_GUARD,
        &gate,
    )?;
    create_tree(&mut writer, &payload, &gate)?;
    copy_files(
        &source_root,
        &payload,
        &manifest,
        false,
        &io,
        &writer,
        &gate,
        cx,
    )?;
    if snapshot(
        &source_root,
        deployment_limits,
        limits,
        &io,
        SnapshotKind::Source,
    )? != manifest
        || snapshot(
            &payload,
            deployment_limits,
            limits,
            &io,
            SnapshotKind::BundlePayload,
        )? != manifest
    {
        return Err(BackupError::Changed);
    }
    checkpoint(cx, STAGE_BACKUP_PUBLISH)?;
    gate()?;
    writer.check()?;
    // Once publication begins, any write/fsync failure may have left the complete pinned
    // manifest visible. Report that ambiguity explicitly instead of claiming cancellation.
    writer
        .write_new(
            &bundle_root.join(BACKUP_MANIFEST_FILENAME),
            &manifest_bytes,
            &gate,
        )
        .map_err(|_| BackupError::Indeterminate)?;
    writer
        .sync_directory(bundle_root.parent().ok_or(BackupError::InvalidPath)?, &gate)
        .map_err(|_| BackupError::Indeterminate)?;
    cx.checkpoint_post_commit(STAGE_BACKUP_PUBLISH);
    Ok(BackupReceipt { manifest })
}

fn read_bundle(
    bundle: &Path,
    expected_manifest: ContentDigest,
    limits: BackupLimits,
    io: &ReadIo<'_>,
) -> Result<BackupManifest> {
    let result = read_bundle_inner(bundle, expected_manifest, limits, io);
    io.check()?;
    result
}

fn read_bundle_inner(
    bundle: &Path,
    expected_manifest: ContentDigest,
    limits: BackupLimits,
    io: &ReadIo<'_>,
) -> Result<BackupManifest> {
    directory(bundle)?;
    let mut entries = SpoolIo::read_dir(io, bundle)?;
    let mut count = 0;
    while let Some(entry) = SpoolIo::next_dir_entry(io, &mut entries) {
        io.check()?;
        let entry = entry?;
        count += 1;
        if count > 2 {
            return Err(BackupError::Unsupported("bundle_entry"));
        }
        let name = entry.file_name();
        let meta = SpoolIo::symlink_metadata(io, &entry.path())?;
        if (name == BACKUP_MANIFEST_FILENAME && meta.is_file())
            || (name == BACKUP_PAYLOAD_DIRECTORY && meta.is_dir())
        {
            continue;
        }
        return Err(BackupError::Unsupported("bundle_entry"));
    }
    if count != 2 {
        return Err(BackupError::RecoveryRequired("bundle_incomplete"));
    }
    let bytes = io.read_exact(
        &bundle.join(BACKUP_MANIFEST_FILENAME),
        limits.max_manifest_bytes as u64,
    )?;
    let manifest = BackupManifest::from_bytes(&bytes, expected_manifest, limits)?;
    let observed = snapshot(
        &bundle.join(BACKUP_PAYLOAD_DIRECTORY),
        *manifest.deployment_limits(),
        limits,
        io,
        SnapshotKind::BundlePayload,
    )?;
    if observed != manifest {
        return Err(BackupError::Changed);
    }
    Ok(manifest)
}

/// Verify a pinned bundle without creating files, probing a writer or reconciling effects.
pub fn inspect_backup(
    bundle: &Path,
    expected_manifest: ContentDigest,
    limits: BackupLimits,
    authority: &dyn BackupAuthority,
    cx: &ReplayCx,
) -> Result<BackupManifest> {
    limits.validate()?;
    let gate = || {
        authorize(
            authority,
            BackupAccess::ReadBundle {
                bundle,
                manifest: expected_manifest,
            },
            cx,
        )
    };
    gate()?;
    let io = ReadIo::new(cx, &gate, limits);
    read_bundle(bundle, expected_manifest, limits, &io)
}

fn fence_capacity(
    manifest: &BackupManifest,
    fence: &RestoreFence,
    limits: BackupLimits,
) -> Result<()> {
    let deployment = manifest.deployment_limits();
    let mut count = 0_usize;
    let mut bytes = 0_u64;
    for file in manifest.files() {
        if file.relative_path().starts_with("objects/spool/objects/") {
            count += 1;
            bytes = bytes
                .checked_add(
                    file.byte_len()
                        .checked_sub(fss_object::SPOOL_OBJECT_HEADER_LEN as u64)
                        .ok_or(BackupError::Corrupt("spool_envelope"))?,
                )
                .ok_or(BackupError::Limit("spool_bytes"))?;
        }
    }
    for extra in [manifest.to_bytes(), fence.to_bytes()] {
        if extra.len() as u64 > deployment.spool_object_max_bytes {
            return Err(BackupError::Limit("restore_metadata_object"));
        }
        bytes = bytes
            .checked_add(extra.len() as u64)
            .ok_or(BackupError::Limit("spool_bytes"))?;
        count = count
            .checked_add(1)
            .ok_or(BackupError::Limit("spool_objects"))?;
    }
    if count > deployment.spool_max_objects
        || bytes > deployment.spool_total_max_bytes
        || deployment.batch_entries_max < 2
    {
        return Err(BackupError::Limit("restore_fence_capacity"));
    }
    if manifest.ledger_bytes() >= limits.max_journal_bytes as u64 {
        return Err(BackupError::Limit("restore_journal_capacity"));
    }
    Ok(())
}

fn append_fence(
    destination: &Path,
    writer: &Arc<WriteTree>,
    manifest: &BackupManifest,
    fence: &RestoreFence,
    limits: BackupLimits,
    gate: &dyn Fn() -> Result<()>,
) -> Result<(
    LocalRootPublisher,
    DurableReferenceLedger,
    fss_core::LedgerAnchor,
    ContentDigest,
    fs::File,
)> {
    gate()?;
    writer.check()?;
    let mut publisher = LocalRootPublisher::open_with_io(
        destination.join("objects"),
        manifest.deployment_limits().to_publication_limits(),
        Arc::new(PinnedSpoolIo::new(Arc::clone(writer))),
    )
    .map_err(|_| BackupError::Corrupt("restore_publication"))?;
    gate()?;
    // Native ledger APIs reopen their path while checking a committed prefix. Give them the
    // existing journal's held descriptor, not a mutable pathname through destination parents.
    // Keep this pin alive for the entire native owner lifetime and activation.
    let journal_pin = writer.open_read(&destination.join("ledger/journal.fssj"))?;
    match journal_pin.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Err(BackupError::Locked),
        Err(fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    let mut ledger = DurableReferenceLedger::open(
        writer.held_file_path(&journal_pin)?,
        manifest.site(),
        IncompleteTailPolicy::Reject,
    )
    .map_err(|_| BackupError::Corrupt("restore_authority"))?;
    if &ledger.current().anchor != manifest.source_anchor()
        || ledger.journal_root() != manifest.ledger_root()
    {
        return Err(BackupError::Changed);
    }
    for bytes in [manifest.to_bytes(), fence.to_bytes()] {
        gate()?;
        writer.check()?;
        let expected = ContentDigest::sha256(&bytes);
        let staged = publisher
            .stage_object(&bytes)
            .map_err(|_| BackupError::RecoveryRequired("restore_metadata_staging"))?;
        if staged != expected {
            return Err(BackupError::Corrupt("restore_metadata_digest"));
        }
        gate()?;
        publisher
            .verify_object(staged)
            .map_err(|_| BackupError::Corrupt("restore_metadata_custody"))?;
    }
    let object = ObjectId::parse(RESTORE_FENCE_OBJECT_ID)?;
    let prior = ledger.current().objects.get(&object);
    if prior.is_some_and(|p| p.family != FAMILY_RESTORE_FENCE || p.plane != Plane::Authority) {
        return Err(BackupError::Corrupt("restore_fence_namespace"));
    }
    let prior_generation = prior.map(|p| p.generation);
    let new_generation = prior_generation
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(BackupError::Limit("restore_fence_generation"))?;
    let delta = EvidenceDelta {
        delta_id: format!("delta:deployment-restore:{}", manifest.digest().to_text()),
        family: FAMILY_RESTORE_FENCE.into(),
        object_id: object,
        prior_generation,
        new_generation,
        validity: CaptureInterval::new(TimestampNs(0), TimestampNs(0))?,
        plane: Plane::Authority,
        payload_digest: fence.digest(),
        witness_digest: Some(manifest.digest()),
        operation_id: None,
    };
    gate()?;
    let mut owner = AuthorityPublisher::new(&publisher, &mut ledger);
    let batch = owner
        .prepare_batch(
            BatchId::parse(format!(
                "batch:deployment-restore:{}",
                manifest.digest().to_text()
            ))?,
            vec![delta],
            [manifest.digest(), fence.digest()],
        )
        .map_err(|_| BackupError::Corrupt("restore_fence_prepare"))?;
    let encoded_len = fss_ledger::encode_batch(&batch)
        .map_err(|_| BackupError::Corrupt("restore_fence_encoding"))?
        .len();
    if encoded_len > manifest.deployment_limits().journal_record_max_bytes as usize
        || manifest
            .ledger_bytes()
            .saturating_add(encoded_len as u64)
            .saturating_add(256)
            > limits.max_journal_bytes as u64
    {
        return Err(BackupError::Limit("restore_fence_journal"));
    }
    gate()?;
    writer.check()?;
    let anchor = owner
        .append(batch)
        .map_err(|_| BackupError::RecoveryRequired("restore_fence_append"))?;
    drop(owner);
    writer.check()?;
    let root = ledger.journal_root();
    Ok((publisher, ledger, anchor, root, journal_pin))
}

/// Restore only to a fresh destination. All bundle validation precedes destination creation;
/// every original byte is copied exactly, then a retained irreversible alert fence advances the
/// copied authority head. LAYOUT and the incomplete marker are the final activation boundary.
pub fn restore_backup(
    bundle: &Path,
    destination: &Path,
    expected_manifest: ContentDigest,
    limits: BackupLimits,
    authority: &dyn BackupAuthority,
    cx: &ReplayCx,
) -> Result<RestoreReceipt> {
    limits.validate()?;
    let gate = || {
        authorize(
            authority,
            BackupAccess::ReadBundle {
                bundle,
                manifest: expected_manifest,
            },
            cx,
        )?;
        authorize(
            authority,
            BackupAccess::RestoreDeployment {
                bundle,
                destination,
                manifest: expected_manifest,
            },
            cx,
        )
    };
    gate()?;
    let bundle_root = directory(bundle)?;
    let destination_root = fresh_path(destination, &[&bundle_root])?;
    let io = ReadIo::new(cx, &gate, limits);
    let manifest = read_bundle(&bundle_root, expected_manifest, limits, &io)?;
    let fence = RestoreFence::new(&manifest);
    fence_capacity(&manifest, &fence, limits)?;
    let payload = bundle_root.join(BACKUP_PAYLOAD_DIRECTORY);
    let layout = io.read_exact(&payload.join("LAYOUT"), 4096)?;
    let marker = format!(
        "fss.deployment_restore.incomplete.v1\nmanifest={}\n",
        expected_manifest.to_text()
    );
    gate()?;
    let mut writer = WriteTree::reserve(&destination_root, &gate)?;
    // Reserve first, so neither an interrupted copy nor an empty-looking journal tree can be
    // initialized by another deployment opener.
    writer.write_new(
        &destination_root.join(RESTORE_INCOMPLETE_FILENAME),
        marker.as_bytes(),
        &gate,
    )?;
    checkpoint(cx, STAGE_RESTORE_RESERVED)?;
    create_tree(&mut writer, &destination_root, &gate)?;
    let writer = Arc::new(writer);
    copy_files(
        &payload,
        &destination_root,
        &manifest,
        true,
        &io,
        &writer,
        &gate,
        cx,
    )?;
    // Revalidate all source custody and authority after copying, before extending destination
    // history. A bundle changed during transfer never acquires an active restored LAYOUT.
    if read_bundle(&bundle_root, expected_manifest, limits, &io)? != manifest {
        return Err(BackupError::Changed);
    }
    // Keep both owners, including the publisher/spool locks, through the activation point.
    let (_publisher, ledger, destination_anchor, destination_ledger_root, _journal_pin) =
        append_fence(&destination_root, &writer, &manifest, &fence, limits, &gate)?;
    checkpoint(cx, STAGE_RESTORE_FENCED)?;
    let mut actual_journal = writer.open_read(&destination_root.join("ledger/journal.fssj"))?;
    if fss_ledger::store_pin_of(
        fss_ledger::STORE_ROLE_AUTHORITY_LEDGER,
        &actual_journal.metadata()?,
    ) != ledger.store_pin()
    {
        return Err(BackupError::Changed);
    }
    let ledger_bytes = io.read_owned(&mut actual_journal, limits.max_journal_bytes as u64)?;
    let prefix = ledger_bytes
        .get(..manifest.ledger_bytes() as usize)
        .ok_or(BackupError::Corrupt("restore_prefix"))?;
    let original_ledger = manifest
        .files()
        .iter()
        .find(|f| f.relative_path() == "ledger/journal.fssj")
        .ok_or(BackupError::Corrupt("restore_prefix"))?;
    if ContentDigest::sha256(prefix) != original_ledger.digest() {
        return Err(BackupError::Corrupt("restore_prefix"));
    }
    for file in manifest.files().iter().filter(|file| {
        file.relative_path() != "LAYOUT" && file.relative_path() != "ledger/journal.fssj"
    }) {
        let bytes = io.read_owned(
            &mut writer.open_read(&destination_root.join(file.relative_path()))?,
            file.byte_len(),
        )?;
        if ContentDigest::sha256(&bytes) != file.digest() {
            return Err(BackupError::Changed);
        }
    }
    if io.read_owned(
        &mut writer.open_read(&destination_root.join(RESTORE_INCOMPLETE_FILENAME))?,
        marker.len() as u64,
    )? != marker.as_bytes()
    {
        return Err(BackupError::Changed);
    }
    checkpoint(cx, STAGE_RESTORE_ACTIVATE)?;
    gate()?;
    writer.write_new(&destination_root.join("LAYOUT"), &layout, &gate)?;
    gate()?;
    writer.remove_marker(&destination_root.join(RESTORE_INCOMPLETE_FILENAME), &gate)?;
    cx.checkpoint_post_commit(STAGE_RESTORE_ACTIVATE);
    Ok(RestoreReceipt {
        manifest,
        destination_anchor,
        destination_ledger_root,
        fence_digest: fence.digest(),
    })
}
