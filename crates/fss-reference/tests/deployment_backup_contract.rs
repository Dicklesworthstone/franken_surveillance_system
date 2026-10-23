#![forbid(unsafe_code)]
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
//! Exact local recovery through real journals, held/deleted originals and root-last custody.
//! Cancellation cuts are deterministic reference faults, not power-loss qualification.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, Generation, ObjectId, OperationId,
    RootAuthoritySpec, SensorId, StreamId, TimestampNs, TombstoneReason, TombstoneRecord,
};
use fss_reference::deletion::holds::{
    CAP_HOLD_COMMIT, CAP_HOLD_PREPARE, HoldRequest, HoldState, commit_hold, list_holds,
    preview_hold,
};
use fss_reference::deletion::{
    DeletionIndex, STAGE_DELETION_RECORD_APPENDED, commit_deletion, plan_deletion,
};
use fss_reference::deployment_backup::*;
use fss_reference::ingest::{
    FileFormatHint, FileIngestAdapter, FileIngestError, FileIngestLimits, FileIngestRequest,
    RetainedFileImport, RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{DeploymentLimits, ReferenceDeployment, ReplayCx};

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:deployment-backup";
const PRINCIPAL: &str = "principal:recovery-owner";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for number in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-backup-{label}-{}-{number}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test temporary-directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Grant;
impl BackupAuthority for Grant {
    fn permit(&self, _: BackupAccess<'_>) -> bool {
        true
    }
}
struct Deny;
impl BackupAuthority for Deny {
    fn permit(&self, _: BackupAccess<'_>) -> bool {
        false
    }
}
struct ExactGrant {
    source: PathBuf,
    bundle: PathBuf,
    destination: PathBuf,
    manifest: ContentDigest,
}
impl BackupAuthority for ExactGrant {
    fn permit(&self, access: BackupAccess<'_>) -> bool {
        match access {
            BackupAccess::ReadDeployment { source } => source == self.source,
            BackupAccess::WriteBundle {
                source,
                bundle,
                manifest,
            } => source == self.source && bundle == self.bundle && manifest == self.manifest,
            BackupAccess::ReadBundle { bundle, manifest } => {
                bundle == self.bundle && manifest == self.manifest
            }
            BackupAccess::RestoreDeployment {
                bundle,
                destination,
                manifest,
            } => {
                bundle == self.bundle
                    && destination == self.destination
                    && manifest == self.manifest
            }
        }
    }
}

struct Fixture {
    directory: Directory,
    authority: ContextAuthority,
    source: PathBuf,
    limits: DeploymentLimits,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:deployment-backup".into(),
            operation_id: OperationId::parse("operation:deployment-backup")?,
            principal: PRINCIPAL.into(),
            capabilities: vec![
                "ADP-REPLAY-001".into(),
                CAP_HOLD_PREPARE.into(),
                CAP_HOLD_COMMIT.into(),
            ],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(64 * 1024 * 1024)
                .storage_operations(1_000_000)
                .build()?,
            privacy_scope: "privacy:originals-explicitly-approved".into(),
            retention_scope: "retention:recovery-fixture".into(),
            anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
            generation: 1,
        })?;
        let source = directory.0.join("source");
        let limits = DeploymentLimits {
            spool_object_max_bytes: 2 * 1024 * 1024,
            spool_total_max_bytes: 32 * 1024 * 1024,
            max_roots: 64,
            max_tombstones: 128,
            spool_max_objects: 4096,
            scan_max_objects: 8192,
            batch_entries_max: 128,
            manifest_children_max: 128,
            journal_record_max_bytes: 2 * 1024 * 1024,
        };
        let result = Self {
            directory,
            authority,
            source,
            limits,
        };
        drop(result.open()?);
        Ok(result)
    }
    fn cx(&self) -> Test<ReplayCx> {
        Ok(ReplayCx::from_context_authority(
            &self.authority,
            self.directory.0.clone(),
        )?)
    }
    fn open(&self) -> Test<ReferenceDeployment> {
        Ok(ReferenceDeployment::open_with_limits(
            &self.source,
            SITE,
            self.limits,
            &self.cx()?,
        )?)
    }
    fn plan(&self) -> Test<BackupManifest> {
        Ok(prepare_backup(
            &self.source,
            self.limits,
            BackupLimits::default(),
            &Grant,
            &self.cx()?,
        )?)
    }
    fn ingest(
        &self,
        deployment: &mut ReferenceDeployment,
        name: &str,
        gray: u8,
    ) -> Test<ContentDigest> {
        let bytes = encode_jpeg(
            16,
            16,
            &[gray; 256],
            &JpegConfig {
                quality: 90,
                subsampling: Subsampling::Grayscale,
                restart_interval: 0,
                custom_markers: Vec::new(),
            },
        )?;
        let path = self.directory.0.join(format!("{name}.mjpeg"));
        fs::write(&path, bytes)?;
        let request = FileIngestRequest::new(
            path,
            SensorId::parse(format!("sensor:{name}"))?,
            StreamId::parse(format!("stream:{name}"))?,
        )
        .with_receive_time(TimestampNs(1_000_000_000))
        .with_format_hint(FileFormatHint::JpegStream)
        .with_limits(FileIngestLimits {
            chunk_bytes: 64 * 1024,
            ..FileIngestLimits::default()
        });
        Ok(FileIngestAdapter::ingest(request, &self.cx()?, deployment)?.import_identity)
    }
    fn bundle(&self, label: &str, manifest: &BackupManifest) -> Test<PathBuf> {
        let path = self.directory.0.join(label);
        assert_eq!(
            create_backup(
                &self.source,
                &path,
                manifest.digest(),
                self.limits,
                BackupLimits::default(),
                &Grant,
                &self.cx()?
            )?
            .manifest(),
            manifest
        );
        Ok(path)
    }
}

fn bytes_under(path: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    fn walk(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                walk(root, &entry.path(), output)?;
            } else if entry.file_type()?.is_file() {
                output.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    fs::read(entry.path())?,
                );
            }
        }
        Ok(())
    }
    let mut output = BTreeMap::new();
    walk(path, path, &mut output)?;
    Ok(output)
}

#[test]
fn exact_roundtrip_keeps_originals_holds_deletion_and_fresh_store_identity() -> Test {
    let f = Fixture::new("roundtrip")?;
    let mut source = f.open()?;
    let retained = f.ingest(&mut source, "retained", 40)?;
    let deleted = f.ingest(&mut source, "deleted", 180)?;
    let request = HoldRequest {
        hold_id: "incident-keep".into(),
        import_identity: retained,
        state: HoldState::Held,
        reason: "Preserve exact original".into(),
    };
    let source_hold_cx = ReplayCx::from_context_authority(&f.authority, f.source.clone())?;
    let held = preview_hold(&source, &request, &f.authority, &source_hold_cx)?;
    commit_hold(
        &mut source,
        &request,
        held.record.approval(),
        &f.authority,
        &source_hold_cx,
    )?;
    let deletion = plan_deletion(&source, deleted, &f.cx()?)?;
    assert!(deletion.blockers.is_empty(), "{:?}", deletion.blockers);
    commit_deletion(
        &mut source,
        deletion.digest()?,
        deletion.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &f.cx()?,
    )?;
    // A staged, unreferenced original is real custody and must survive too. Its verification
    // marker is retained independently of whether a manifest happens to reference it.
    let unreferenced = source.stage_payload(b"approved-unreferenced-original")?;
    source.publisher_mut().verify_object(unreferenced)?;
    // The deployment deletion owner records authority tombstones in its ledger. Independently
    // exercise an existing local publisher tombstone whose denied original has been removed.
    let local_deleted = source.stage_payload(b"completed-local-original")?;
    let local_witness = source.stage_payload(b"completed-local-deletion-authority")?;
    source.publisher_mut().verify_object(local_witness)?;
    source
        .publisher_mut()
        .record_tombstone(TombstoneRecord::new(
            ObjectId::parse("object:completed-local-deletion")?,
            Generation(2),
            Generation(1),
            TombstoneReason::Deleted,
            Some(local_witness),
            local_deleted,
        )?)?;
    source
        .publisher_mut()
        .remove_deleted_object(local_deleted, local_witness)?;
    assert!(!source.publisher().object_name_present(local_deleted));
    let source_anchor = source.current_anchor().clone();
    let source_ledger_pin = source.ledger().store_pin();
    let source_effect_pin = source.effects().store_pin();
    let source_batches = source.ledger().batches().to_vec();
    let source_roots: Vec<_> = source
        .publisher()
        .visible_roots()
        .map(|r| (r.slot.clone(), r.root))
        .collect();
    drop(source);
    let original = bytes_under(&f.source)?;
    let manifest = f.plan()?;
    assert_eq!(manifest, f.plan()?);
    assert_eq!(manifest.source_anchor(), &source_anchor);
    assert_eq!(manifest.deployment_limits(), &f.limits);
    assert!(
        manifest
            .files()
            .iter()
            .any(|file| file.relative_path().ends_with(&unreferenced.to_text()[7..]))
    );
    assert!(
        manifest
            .files()
            .iter()
            .any(|file| file.relative_path().starts_with("objects/tombstones/"))
    );
    let bundle = f.bundle("bundle", &manifest)?;
    assert_eq!(
        inspect_backup(
            &bundle,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        )?,
        manifest
    );
    let destination = f.directory.0.join("restored");
    let grant = ExactGrant {
        source: f.source.clone(),
        bundle: bundle.clone(),
        destination: destination.clone(),
        manifest: manifest.digest(),
    };
    let receipt = restore_backup(
        &bundle,
        &destination,
        manifest.digest(),
        BackupLimits::default(),
        &grant,
        &f.cx()?,
    )?;
    assert_eq!(
        receipt.destination_anchor().commit_sequence,
        source_anchor.commit_sequence + 1
    );
    assert_eq!(
        receipt.destination_anchor().ledger_epoch,
        source_anchor.ledger_epoch
    );
    assert_ne!(receipt.destination_ledger_root(), manifest.ledger_root());
    assert_eq!(bytes_under(&f.source)?, original);
    for file in manifest.files() {
        let observed = fs::read(destination.join(file.relative_path()))?;
        let preserved = if file.relative_path() == "ledger/journal.fssj" {
            &observed[..file.byte_len() as usize]
        } else {
            &observed
        };
        assert_eq!(
            ContentDigest::sha256(preserved),
            file.digest(),
            "{}",
            file.relative_path()
        );
    }
    let restored = ReferenceDeployment::open_with_limits(&destination, SITE, f.limits, &f.cx()?)?;
    assert_ne!(restored.ledger().store_pin(), source_ledger_pin);
    assert_ne!(restored.effects().store_pin(), source_effect_pin);
    assert_eq!(
        &restored.ledger().batches()[..source_batches.len()],
        source_batches.as_slice()
    );
    assert_eq!(
        restored
            .publisher()
            .visible_roots()
            .map(|r| (r.slot.clone(), r.root))
            .collect::<Vec<_>>(),
        source_roots
    );
    assert_eq!(
        restored.publisher().spool().read(unreferenced)?,
        b"approved-unreferenced-original"
    );
    assert!(
        restored
            .publisher()
            .tombstones()
            .any(|digest| *digest == local_deleted)
    );
    assert!(!restored.publisher().object_name_present(local_deleted));
    let destination_hold_cx = ReplayCx::from_context_authority(&f.authority, destination.clone())?;
    assert_eq!(
        list_holds(&restored, &f.authority, &destination_hold_cx)?,
        vec![held.record]
    );
    assert!(
        !plan_deletion(&restored, retained, &f.cx()?)?
            .blockers
            .is_empty()
    );
    assert!(
        DeletionIndex::read(&restored)?
            .import(deleted)
            .ok_or("missing deletion")?
            .is_complete()
    );
    assert!(matches!(
        RetainedFileImport::open(&restored, deleted, RetainedReadLimits::default(), &f.cx()?),
        Err(FileIngestError::EvidenceDeleted { .. })
    ));
    let record = restored
        .ledger()
        .current()
        .objects
        .get(&ObjectId::parse(RESTORE_FENCE_OBJECT_ID)?)
        .ok_or("missing fence")?;
    assert_eq!(record.family, FAMILY_RESTORE_FENCE);
    let fence = RestoreFence::from_bytes(
        &restored.publisher().spool().read(record.payload_digest)?,
        receipt.fence_digest(),
    )?;
    assert_eq!(fence.source_manifest(), manifest.digest());
    assert_eq!(fence.source_anchor(), &source_anchor);
    assert_eq!(fence.source_effects_root(), manifest.effects_root());
    assert_eq!(fence.source_ledger_root(), manifest.ledger_root());
    assert!(!destination.join(RESTORE_INCOMPLETE_FILENAME).exists());
    Ok(())
}

#[test]
fn payload_is_permanently_inert_and_deleting_guard_invalidates_bundle() -> Test {
    let f = Fixture::new("inert")?;
    let manifest = f.plan()?;
    let bundle = f.bundle("bundle", &manifest)?;
    let payload = bundle.join(BACKUP_PAYLOAD_DIRECTORY);
    let before = bytes_under(&payload)?;
    assert!(ReferenceDeployment::open_with_limits(&payload, SITE, f.limits, &f.cx()?).is_err());
    assert_eq!(bytes_under(&payload)?, before);
    fs::remove_file(payload.join(RESTORE_INCOMPLETE_FILENAME))?;
    let destination = f.directory.0.join("refused");
    assert!(
        restore_backup(
            &bundle,
            &destination,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        )
        .is_err()
    );
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn changed_preview_wrong_pin_and_exact_authority_refuse_before_output_creation() -> Test {
    let f = Fixture::new("authority")?;
    let manifest = f.plan()?;
    let bundle = f.directory.0.join("bundle");
    let destination = f.directory.0.join("destination");
    let grant = ExactGrant {
        source: f.source.clone(),
        bundle: bundle.clone(),
        destination: destination.clone(),
        manifest: manifest.digest(),
    };
    assert_eq!(
        prepare_backup(
            &f.source,
            f.limits,
            BackupLimits::default(),
            &Deny,
            &f.cx()?
        ),
        Err(BackupError::Unauthorized)
    );
    assert!(matches!(
        create_backup(
            &f.source,
            &bundle,
            manifest.digest(),
            f.limits,
            BackupLimits::default(),
            &Deny,
            &f.cx()?
        ),
        Err(BackupError::Unauthorized)
    ));
    assert!(!bundle.exists());
    assert!(matches!(
        create_backup(
            &f.source,
            &f.directory.0.join("other-bundle"),
            manifest.digest(),
            f.limits,
            BackupLimits::default(),
            &grant,
            &f.cx()?
        ),
        Err(BackupError::Unauthorized)
    ));
    let mut deployment = f.open()?;
    deployment.stage_payload(b"new-original-between-preview-and-create")?;
    drop(deployment);
    assert!(matches!(
        create_backup(
            &f.source,
            &bundle,
            manifest.digest(),
            f.limits,
            BackupLimits::default(),
            &grant,
            &f.cx()?
        ),
        Err(BackupError::Changed)
    ));
    assert!(!bundle.exists());
    let current = f.plan()?;
    let bundle = f.bundle("valid-bundle", &current)?;
    assert!(matches!(
        inspect_backup(
            &bundle,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        ),
        Err(BackupError::Changed)
    ));
    assert!(matches!(
        restore_backup(
            &bundle,
            &destination,
            current.digest(),
            BackupLimits::default(),
            &Deny,
            &f.cx()?
        ),
        Err(BackupError::Unauthorized)
    ));
    assert!(!destination.exists());
    Ok(())
}

#[test]
fn held_writer_incomplete_deletion_and_dirty_staging_are_never_repaired_by_backup() -> Test {
    let f = Fixture::new("dirty")?;
    let mut deployment = f.open()?;
    assert!(matches!(
        prepare_backup(
            &f.source,
            f.limits,
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        ),
        Err(BackupError::Locked)
    ));
    let import = f.ingest(&mut deployment, "delete-pending", 90)?;
    let plan = plan_deletion(&deployment, import, &f.cx()?)?;
    let interrupted = f.cx()?;
    interrupted.set_cancel_at_checkpoint(STAGE_DELETION_RECORD_APPENDED);
    assert!(
        commit_deletion(
            &mut deployment,
            plan.digest()?,
            plan.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &interrupted
        )
        .is_err()
    );
    drop(deployment);
    let original = bytes_under(&f.source)?;
    assert!(matches!(
        prepare_backup(
            &f.source,
            f.limits,
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        ),
        Err(BackupError::RecoveryRequired("deletion_incomplete"))
    ));
    assert_eq!(bytes_under(&f.source)?, original);
    let clean = Fixture::new("staging")?;
    fs::write(
        clean.source.join("objects/spool/staging/unfinished.tmp"),
        b"partial original",
    )?;
    let original = bytes_under(&clean.source)?;
    assert!(
        prepare_backup(
            &clean.source,
            clean.limits,
            BackupLimits::default(),
            &Grant,
            &clean.cx()?
        )
        .is_err()
    );
    assert_eq!(bytes_under(&clean.source)?, original);
    Ok(())
}

#[test]
fn unsafe_or_foreign_snapshot_state_refuses_without_destination_or_repair() -> Test {
    for label in ["foreign", "agent", "corrupt", "journal-tail"] {
        let f = Fixture::new(label)?;
        let mut deployment = f.open()?;
        let original = deployment.stage_payload(b"exact original")?;
        drop(deployment);
        match label {
            "foreign" => fs::write(f.source.join("unowned-secrets"), b"must not copy")?,
            "agent" => {
                fs::create_dir(f.source.join("agent"))?;
                fs::write(
                    f.source.join("agent/session"),
                    b"independently locked state",
                )?;
            }
            "corrupt" => {
                let path = f
                    .source
                    .join("objects/spool/objects")
                    .join(&original.to_text()[7..]);
                let mut bytes = fs::read(&path)?;
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                fs::write(path, bytes)?;
            }
            _ => {
                fs::OpenOptions::new()
                    .append(true)
                    .open(f.source.join("ledger/journal.fssj"))?
                    .write_all(b"not a committed journal record")?;
            }
        }
        let before = bytes_under(&f.source)?;
        let destination = f.directory.0.join("bundle");
        assert!(
            create_backup(
                &f.source,
                &destination,
                ContentDigest::sha256(b"unapproved"),
                f.limits,
                BackupLimits::default(),
                &Grant,
                &f.cx()?
            )
            .is_err()
        );
        assert!(!destination.exists());
        assert_eq!(bytes_under(&f.source)?, before);
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_and_hardlink_originals_refuse_and_existing_destinations_are_not_overwritten() -> Test {
    use std::os::unix::fs::symlink;
    for symbolic in [true, false] {
        let f = Fixture::new(if symbolic { "symlink" } else { "hardlink" })?;
        let alias = f.directory.0.join("alias");
        if symbolic {
            symlink(&f.source, &alias)?;
            assert!(
                prepare_backup(&alias, f.limits, BackupLimits::default(), &Grant, &f.cx()?)
                    .is_err()
            );
        } else {
            fs::hard_link(f.source.join("LAYOUT"), &alias)?;
            assert!(
                prepare_backup(
                    &f.source,
                    f.limits,
                    BackupLimits::default(),
                    &Grant,
                    &f.cx()?
                )
                .is_err()
            );
        }
        assert!(alias.exists());
    }
    let f = Fixture::new("existing")?;
    let manifest = f.plan()?;
    let bundle = f.bundle("bundle", &manifest)?;
    let destination = f.directory.0.join("existing");
    fs::create_dir(&destination)?;
    fs::write(destination.join("keep"), b"existing user data")?;
    assert!(matches!(
        restore_backup(
            &bundle,
            &destination,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        ),
        Err(BackupError::DestinationExists)
    ));
    assert_eq!(fs::read(destination.join("keep"))?, b"existing user data");
    let empty = f.directory.0.join("empty");
    fs::create_dir(&empty)?;
    assert!(matches!(
        restore_backup(
            &bundle,
            &empty,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        ),
        Err(BackupError::DestinationExists)
    ));
    assert!(fs::read_dir(&empty)?.next().is_none());
    Ok(())
}

#[test]
fn limits_and_tampered_bundle_are_fully_checked_before_restore_reservation() -> Test {
    let f = Fixture::new("bounds")?;
    let manifest = f.plan()?;
    for limits in [
        BackupLimits {
            max_files: 0,
            ..BackupLimits::default()
        },
        BackupLimits {
            max_file_bytes: 1,
            ..BackupLimits::default()
        },
        BackupLimits {
            max_total_bytes: 1,
            ..BackupLimits::default()
        },
        BackupLimits {
            max_manifest_bytes: 1,
            ..BackupLimits::default()
        },
    ] {
        assert!(prepare_backup(&f.source, f.limits, limits, &Grant, &f.cx()?).is_err());
    }
    let bundle = f.bundle("bundle", &manifest)?;
    let destination = f.directory.0.join("destination");
    assert!(
        restore_backup(
            &bundle,
            &destination,
            manifest.digest(),
            BackupLimits {
                max_manifest_bytes: 1,
                ..BackupLimits::default()
            },
            &Grant,
            &f.cx()?
        )
        .is_err()
    );
    assert!(!destination.exists());
    fs::write(
        bundle.join(BACKUP_PAYLOAD_DIRECTORY).join("LAYOUT"),
        b"wrong layout",
    )?;
    assert!(
        restore_backup(
            &bundle,
            &destination,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        )
        .is_err()
    );
    assert!(!destination.exists());
    let mut bytes = manifest.to_bytes();
    bytes.push(0);
    assert!(
        BackupManifest::from_bytes(
            &bytes,
            ContentDigest::sha256(&bytes),
            BackupLimits::default()
        )
        .is_err()
    );
    assert!(
        BackupManifest::from_bytes(
            &manifest.to_bytes(),
            ContentDigest::sha256(b"wrong external pin"),
            BackupLimits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn cancellation_at_every_restore_boundary_keeps_the_destination_inactive() -> Test {
    let f = Fixture::new("cancel")?;
    let mut source = f.open()?;
    source.stage_payload(b"original copied only under a live grant")?;
    drop(source);
    let manifest = f.plan()?;
    let bundle = f.bundle("bundle", &manifest)?;
    let before = bytes_under(&f.source)?;
    for (index, stage) in [
        STAGE_RESTORE_RESERVED,
        STAGE_BACKUP_COPY,
        STAGE_RESTORE_FENCED,
        STAGE_RESTORE_ACTIVATE,
    ]
    .into_iter()
    .enumerate()
    {
        let destination = f.directory.0.join(format!("cancelled-{index}"));
        let cx = f.cx()?;
        cx.set_cancel_at_checkpoint(stage);
        let restored = restore_backup(
            &bundle,
            &destination,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &cx,
        );
        assert!(
            matches!(restored, Err(BackupError::Cancelled)),
            "restore cut at {stage}: {restored:?}"
        );
        assert!(cx.is_drain_completed());
        assert!(destination.join(RESTORE_INCOMPLETE_FILENAME).is_file());
        assert!(!destination.join("LAYOUT").exists());
        let partial = bytes_under(&destination)?;
        assert!(
            ReferenceDeployment::open_with_limits(&destination, SITE, f.limits, &f.cx()?).is_err()
        );
        assert_eq!(bytes_under(&destination)?, partial);
        if stage == STAGE_RESTORE_FENCED || stage == STAGE_RESTORE_ACTIVATE {
            let ledger = fss_ledger::inspect_durable_with_io(
                &fss_ledger::HostJournalReadIo,
                destination.join("ledger/journal.fssj"),
                SITE,
                fss_ledger::DurableLedgerLimits::default(),
            )?;
            assert_eq!(
                ledger.snapshot.anchor.commit_sequence,
                manifest.source_anchor().commit_sequence + 1
            );
            assert!(
                ledger
                    .snapshot
                    .objects
                    .contains_key(&ObjectId::parse(RESTORE_FENCE_OBJECT_ID)?)
            );
        }
    }
    assert_eq!(bytes_under(&f.source)?, before);
    Ok(())
}

#[test]
fn source_and_destination_authority_remain_live_during_semantic_reads_and_copy() -> Test {
    struct RevokedAfter {
        remaining: AtomicUsize,
    }
    impl BackupAuthority for RevokedAfter {
        fn permit(&self, _: BackupAccess<'_>) -> bool {
            self.remaining
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
        }
    }
    let f = Fixture::new("revocation")?;
    let before = bytes_under(&f.source)?;
    assert!(matches!(
        prepare_backup(
            &f.source,
            f.limits,
            BackupLimits::default(),
            &RevokedAfter {
                remaining: AtomicUsize::new(40)
            },
            &f.cx()?
        ),
        Err(BackupError::Unauthorized)
    ));
    assert_eq!(bytes_under(&f.source)?, before);
    let manifest = f.plan()?;
    let destination = f.directory.0.join("cancelled-bundle");
    let cx = f.cx()?;
    cx.set_cancel_at_checkpoint(STAGE_BACKUP_PUBLISH);
    assert!(matches!(
        create_backup(
            &f.source,
            &destination,
            manifest.digest(),
            f.limits,
            BackupLimits::default(),
            &Grant,
            &cx
        ),
        Err(BackupError::Cancelled)
    ));
    assert!(!destination.join(BACKUP_MANIFEST_FILENAME).exists());
    assert!(
        inspect_backup(
            &destination,
            manifest.digest(),
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        )
        .is_err()
    );
    assert_eq!(bytes_under(&f.source)?, before);
    Ok(())
}

#[test]
fn local_tombstone_without_ledger_deletion_cannot_resurrect_retained_original_bytes() -> Test {
    let f = Fixture::new("local-tombstone")?;
    let mut source = f.open()?;
    let original = source.stage_payload(b"locally-denied-unreferenced-original")?;
    let witness = source.stage_payload(b"local-deletion-authority")?;
    source.publisher_mut().verify_object(witness)?;
    source
        .publisher_mut()
        .record_tombstone(TombstoneRecord::new(
            ObjectId::parse("object:locally-denied")?,
            Generation(2),
            Generation(1),
            TombstoneReason::Deleted,
            Some(witness),
            original,
        )?)?;
    assert!(DeletionIndex::read(&source)?.is_empty());
    assert!(source.publisher().object_name_present(original));
    drop(source);
    let before = bytes_under(&f.source)?;
    let preview = prepare_backup(
        &f.source,
        f.limits,
        BackupLimits::default(),
        &Grant,
        &f.cx()?,
    );
    assert!(
        matches!(
            preview,
            Err(BackupError::RecoveryRequired("deleted_bytes_remain"))
        ),
        "local tombstone preview: {preview:?}"
    );
    let destination = f.directory.0.join("refused-bundle");
    assert!(
        create_backup(
            &f.source,
            &destination,
            ContentDigest::sha256(b"no-approved-resurrection"),
            f.limits,
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        )
        .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(bytes_under(&f.source)?, before);
    Ok(())
}

#[test]
fn valid_spool_and_ledger_cannot_hide_an_invalid_hold_transition() -> Test {
    use fss_core::BatchId;
    use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
    use fss_reference::deletion::holds::HoldRecord;
    use fss_reference::reference_deployment::FAMILY_EVIDENCE_HOLD;

    let f = Fixture::new("invalid-hold-transition")?;
    let mut source = f.open()?;
    let retained = f.ingest(&mut source, "retained", 90)?;
    let hold_cx = ReplayCx::from_context_authority(&f.authority, f.source.clone())?;
    let request = HoldRequest {
        hold_id: "preserve-original".into(),
        import_identity: retained,
        state: HoldState::Held,
        reason: "Preserve the retained original".into(),
    };
    let preview = preview_hold(&source, &request, &f.authority, &hold_cx)?;
    let held = commit_hold(
        &mut source,
        &request,
        preview.record.approval(),
        &f.authority,
        &hold_cx,
    )?
    .record;
    let mut forged = source
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| &batch.deltas)
        .find(|delta| delta.family == FAMILY_EVIDENCE_HOLD)
        .ok_or("committed hold delta missing")?
        .clone();
    forged.delta_id = "delta:backup-forged-hold-successor".into();
    forged.prior_generation = Some(1);
    forged.new_generation = 2;
    forged.witness_digest = Some(held.digest());
    let object_id = forged.object_id.clone();
    drop(source);

    // Author a malformed retained history below the hold owner. The general ledger permits
    // this generation update, and its unchanged payload is still an exact canonical Held
    // record. It cannot serve as the authority for a second-generation hold transition.
    let journal = f.source.join("ledger/journal.fssj");
    let mut ledger = DurableReferenceLedger::open(&journal, SITE, IncompleteTailPolicy::Reject)?;
    let batch = ledger.prepare_batch(
        BatchId::parse("batch:backup-forged-hold-successor")?,
        vec![forged],
        vec![held.digest()],
    )?;
    ledger.append(batch)?;
    drop(ledger);
    let ledger = fss_ledger::inspect_durable(&journal, SITE, 4 * 1024 * 1024_usize)?;
    assert!(ledger.is_clean());
    assert_eq!(ledger.snapshot.objects[&object_id].generation, 2);
    let bytes = fss_publication::read_verified(
        f.source.join("objects"),
        held.digest(),
        fss_reference::deletion::holds::MAX_HOLD_RECORD_BYTES,
    )?;
    assert_eq!(HoldRecord::from_bytes(&bytes, held.digest())?, held);

    let before = bytes_under(&f.source)?;
    assert!(matches!(
        prepare_backup(
            &f.source,
            f.limits,
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        ),
        Err(BackupError::Corrupt("hold_authority"))
    ));
    let bundle = f.directory.0.join("refused-invalid-hold-bundle");
    assert!(matches!(
        create_backup(
            &f.source,
            &bundle,
            ContentDigest::sha256(b"invalid-hold-has-no-approved-manifest"),
            f.limits,
            BackupLimits::default(),
            &Grant,
            &f.cx()?
        ),
        Err(BackupError::Corrupt("hold_authority"))
    ));
    assert!(!bundle.exists());
    assert_eq!(bytes_under(&f.source)?, before);
    Ok(())
}

#[path = "deployment_backup_contract/agent.rs"]
mod agent;
