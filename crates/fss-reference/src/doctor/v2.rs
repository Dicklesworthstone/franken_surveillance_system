#![forbid(unsafe_code)]
//! Strictly read-only, lock-free inspection of v2 deployment roots (`LAYOUT` v2,
//! `ledger/epochs/`, `objects/packs/`, `projections/mvcc/`, optional `effects/journal.fssj`).
//!
//! Never acquires `<root>/LOCK`, never creates directories, never modifies or quarantines files.

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use fss_core::ContentDigest;
use fss_ledger::inspect_epochs_readonly;
use fss_pack::{PACK_FOOTER_END_MAGIC, PackId, verify_sealed_pack};
use fss_projection_store::{ProjectionSnapshot, inspect_wal_readonly};
use fss_publication::{WriterDetectionOptions, detect_writers};

use crate::migration::{DeploymentLayoutV2, MIGRATE_INCOMPLETE_FILENAME};
use crate::reference_deployment::DeploymentLimits;

use super::{
    DOCTOR_SCHEMA, DoctorAffordance, DoctorCheck, DoctorIo, DoctorLimits, DoctorReport,
    DoctorSeverity, DoctorValue, DoctorVerdict, JournalKind, VERSION, effects_inspection,
    journal_check, num64, obligations_check, read_journal, rerun_doctor, text, writer_check,
};

const MAX_MVCC_SNAP_READ_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SEALED_PACKS_VERIFIED_PER_DOCTOR: usize = 64;

pub(super) fn inspect_v2_deployment(
    io: DoctorIo<'_>,
    root: &Path,
    layout: &DeploymentLayoutV2,
    layout_digest: ContentDigest,
    limits: DoctorLimits,
) -> DoctorReport {
    let objects_dir = root.join(&layout.objects_relpath);
    let ledger_dir = root.join(&layout.ledger_relpath);
    let projections_dir = root.join(&layout.projections_relpath);
    let effects_file = root.join(&layout.effects_relpath);
    let packs_dir = objects_dir.join("packs");
    let epochs_dir = ledger_dir.join("epochs");

    // 1. Layout check (format_version = 2)
    let mut layout_check = DoctorCheck::new("deployment.layout");
    layout_check.evidence("layout_sha256", layout_digest);
    layout_check.evidence("limits_digest", layout.limits_digest);
    layout_check.field("format_version", num64(u64::from(layout.format_version)));
    layout_check.field("site_lineage", text(&layout.site_lineage));
    if let Ok(std_digest) = DeploymentLimits::standard().canonical_digest()
        && std_digest == layout.limits_digest
    {
        layout_check.field("limits_profile", text("standard"));
    } else {
        layout_check.field("limits_profile", text("custom"));
    }

    let incomplete_marker = root.join(MIGRATE_INCOMPLETE_FILENAME);
    if io.fs.symlink_metadata(&incomplete_marker).is_ok() {
        layout_check.find(
            "migrate_incomplete",
            DoctorSeverity::Attention,
            None,
            Some(DoctorAffordance::owner(
                "discard_incomplete_migration",
                "destination carries .migrate-incomplete; remove and re-run `fss migrate`",
            )),
        );
    }

    for (name, dir) in [
        ("objects", objects_dir.as_path()),
        ("objects.packs", packs_dir.as_path()),
        ("ledger", ledger_dir.as_path()),
        ("ledger.epochs", epochs_dir.as_path()),
    ] {
        match io.fs.symlink_metadata(dir) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            _ => {
                layout_check.field("missing_directory", text(name));
                layout_check.find("missing_directory", DoctorSeverity::Attention, None, None);
            }
        }
    }

    // 2. Writer detection (lock-free observation of <root>/LOCK)
    let lock_paths = vec![root.join("LOCK")];
    let writer_state = detect_writers(
        io.fs,
        &lock_paths,
        Some(io.lock_table),
        WriterDetectionOptions::default(),
    );
    let rerun = rerun_doctor(root);
    let mut writer_chk = writer_check(&writer_state, &rerun);
    let possibly_stale = writer_state.possibly_stale();
    writer_chk.field("possibly_stale", DoctorValue::Bool(possibly_stale));

    // 3. Segmented Merkle epoch ledger verification (strictly read-only, zero locks)
    let mut epochs_check = DoctorCheck::new("ledger.epochs");
    match inspect_epochs_readonly(&ledger_dir, &layout.site_lineage) {
        Ok(inspected) => {
            epochs_check.field("epochs_verified", num64(inspected.epochs_verified));
            epochs_check.field("batches_verified", num64(inspected.batches.len() as u64));
            epochs_check.field(
                "head_commit_sequence",
                num64(inspected.head_anchor.commit_sequence),
            );
            epochs_check.field("live_objects", num64(inspected.live_objects));
            epochs_check.field(
                "incomplete_tail",
                DoctorValue::Bool(inspected.incomplete_tail),
            );
            epochs_check.evidence("history_root", inspected.history_root);
            epochs_check.evidence("state_root", inspected.head_anchor.state_root);
            if inspected.incomplete_tail {
                epochs_check.find(
                    "incomplete_tail",
                    if writer_state.is_held() {
                        DoctorSeverity::Info
                    } else {
                        DoctorSeverity::Attention
                    },
                    None,
                    Some(rerun.clone()),
                );
            }
        }
        Err(err) => {
            epochs_check.field("error", DoctorValue::String(err.to_string()));
            epochs_check.find(
                "epoch_ledger_corrupt",
                DoctorSeverity::Attention,
                None,
                None,
            );
        }
    }

    // 4. Sealed & active packfiles read-only verification
    let packs_check = inspect_packs_readonly(&packs_dir);

    // 5. Derived MVCC projection presence and scrub status
    let projection_check = inspect_projection_readonly(&projections_dir);

    // 6. Optional effects journal & obligations
    let effects_read = read_journal(io.files, &effects_file, limits.max_journal_bytes);
    let effects_chk = journal_check(
        "effects.journal",
        JournalKind::Effects,
        &effects_file,
        &effects_read,
        writer_state.is_held(),
        root,
        &rerun,
    );
    let obligations_chk = match effects_inspection(&effects_file, &effects_read, limits) {
        Ok(eff_report) => obligations_check(&eff_report, root, limits),
        Err(unavailable) => unavailable.check("effects.obligations"),
    };

    let checks: Vec<DoctorCheck> = vec![
        layout_check,
        writer_chk,
        epochs_check,
        packs_check,
        projection_check,
        effects_chk,
        obligations_chk,
    ]
    .into_iter()
    .map(DoctorCheck::finalized)
    .collect();

    let verdict = if checks
        .iter()
        .any(|check| check.severity == DoctorSeverity::Attention)
    {
        DoctorVerdict::AttentionRequired
    } else {
        DoctorVerdict::Healthy
    };

    DoctorReport {
        schema: DOCTOR_SCHEMA.to_owned(),
        version: VERSION.to_owned(),
        root: Some(root.to_path_buf()),
        verdict,
        possibly_stale,
        limits,
        checks,
    }
}

fn inspect_packs_readonly(packs_dir: &Path) -> DoctorCheck {
    let mut check = DoctorCheck::new("objects.packs");
    let Ok(entries) = fs::read_dir(packs_dir) else {
        check.field(
            "reason",
            text("objects/packs directory is missing or unreadable"),
        );
        check.find(
            "packs_dir_unreadable",
            DoctorSeverity::Attention,
            None,
            None,
        );
        return check;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("fssp"))
        .collect();
    paths.sort();

    let mut total_packs = 0_u64;
    let mut sealed_packs = 0_u64;
    let mut attempted_sealed = 0_u64;
    let mut verified_sealed = 0_u64;
    let mut total_bytes = 0_u64;
    let mut corrupt_packs = 0_u64;
    let mut symlink_packs = 0_u64;
    let mut unrecognized_pack_names = 0_u64;

    for path in &paths {
        let Ok(meta) = fs::symlink_metadata(path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            symlink_packs = symlink_packs.saturating_add(1);
            check.find(
                "symlink_pack_entry",
                DoctorSeverity::Attention,
                Some(usize::try_from(symlink_packs).unwrap_or(usize::MAX)),
                None,
            );
            continue;
        }
        if !meta.file_type().is_file() {
            continue;
        }
        total_packs = total_packs.saturating_add(1);
        total_bytes = total_bytes.saturating_add(meta.len());

        let is_sealed = File::open(path)
            .ok()
            .and_then(|mut f| {
                let opened_meta = f.metadata().ok()?;
                if !opened_meta.file_type().is_file() || opened_meta.len() < 4 {
                    return None;
                }
                f.seek(SeekFrom::End(-4)).ok()?;
                let mut tail = [0_u8; 4];
                f.read_exact(&mut tail).ok()?;
                Some(tail == PACK_FOOTER_END_MAGIC)
            })
            .unwrap_or(false);

        if is_sealed {
            sealed_packs = sealed_packs.saturating_add(1);
            let parsed_id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(parse_pack_id_stem);
            match parsed_id {
                Some(pack_id) => {
                    if attempted_sealed < MAX_SEALED_PACKS_VERIFIED_PER_DOCTOR as u64 {
                        attempted_sealed = attempted_sealed.saturating_add(1);
                        match verify_sealed_pack(packs_dir, pack_id) {
                            Ok(_) => verified_sealed = verified_sealed.saturating_add(1),
                            Err(err) => {
                                corrupt_packs = corrupt_packs.saturating_add(1);
                                check.field(
                                    "last_pack_error",
                                    DoctorValue::String(format!("pack {pack_id}: {err}")),
                                );
                                check.find(
                                    "sealed_pack_corrupt",
                                    DoctorSeverity::Attention,
                                    Some(usize::try_from(corrupt_packs).unwrap_or(usize::MAX)),
                                    None,
                                );
                            }
                        }
                    }
                }
                None => {
                    unrecognized_pack_names = unrecognized_pack_names.saturating_add(1);
                    check.find(
                        "unrecognized_pack_filename",
                        DoctorSeverity::Attention,
                        Some(usize::try_from(unrecognized_pack_names).unwrap_or(usize::MAX)),
                        None,
                    );
                }
            }
        }
    }

    let recognized_sealed = sealed_packs.saturating_sub(unrecognized_pack_names);
    let verification_bounded = recognized_sealed > attempted_sealed;
    if verification_bounded {
        check.find(
            "pack_verification_bounded",
            DoctorSeverity::Info,
            Some(usize::try_from(sealed_packs).unwrap_or(usize::MAX)),
            None,
        );
    }

    check.field("pack_count", num64(total_packs));
    check.field("sealed_pack_count", num64(sealed_packs));
    check.field("verified_sealed_packs", num64(verified_sealed));
    check.field(
        "verification_bounded",
        DoctorValue::Bool(verification_bounded),
    );
    check.field("on_disk_pack_bytes", num64(total_bytes));
    check.field("corrupt_pack_count", num64(corrupt_packs));
    check.field("symlink_pack_count", num64(symlink_packs));
    check.field(
        "unrecognized_pack_name_count",
        num64(unrecognized_pack_names),
    );
    check
}

fn parse_pack_id_stem(stem: &str) -> Option<PackId> {
    let rest = stem.strip_prefix("pack-")?;
    let (epoch_hex, seq_hex) = rest.split_once('-')?;
    let epoch = u32::from_str_radix(epoch_hex, 16).ok()?;
    let seq = u64::from_str_radix(seq_hex, 16).ok()?;
    Some(PackId::new(epoch, seq))
}

fn inspect_projection_readonly(proj_dir: &Path) -> DoctorCheck {
    let mut check = DoctorCheck::new("projections.mvcc");
    let snap_path = proj_dir.join("mvcc.snap");
    let wal_path = proj_dir.join("mvcc.wal");
    let snap_meta = fs::symlink_metadata(&snap_path).ok();
    let wal_meta = fs::symlink_metadata(&wal_path).ok();
    let snap_is_symlink = snap_meta
        .as_ref()
        .is_some_and(|m| m.file_type().is_symlink());
    let wal_is_symlink = wal_meta
        .as_ref()
        .is_some_and(|m| m.file_type().is_symlink());
    if snap_is_symlink || wal_is_symlink {
        check.field("symlink_projection_entry", DoctorValue::Bool(true));
        check.find(
            "projection_symlink_entry",
            DoctorSeverity::Attention,
            None,
            None,
        );
    }
    let has_snap = snap_meta
        .as_ref()
        .is_some_and(|m| m.file_type().is_file() && !m.file_type().is_symlink());
    let has_wal = wal_meta
        .as_ref()
        .is_some_and(|m| m.file_type().is_file() && !m.file_type().is_symlink());
    check.field("snapshot_present", DoctorValue::Bool(has_snap));
    check.field("wal_present", DoctorValue::Bool(has_wal));
    if !has_snap && !has_wal {
        if !snap_is_symlink && !wal_is_symlink {
            check.field(
                "reason",
                text("derived MVCC projection directory has no snapshot or WAL yet (rebuildable)"),
            );
            check.find(
                "projection_not_materialized",
                DoctorSeverity::Info,
                None,
                None,
            );
        }
        return check;
    }

    let mut snap_seq = 0_u64;
    let mut has_scrub_receipt = false;
    if has_snap {
        let snap_len = snap_meta.as_ref().map_or(0, fs::Metadata::len);
        if snap_len > MAX_MVCC_SNAP_READ_BYTES {
            check.field(
                "reason",
                DoctorValue::String(format!(
                    "derived mvcc.snap size {snap_len} exceeds read-only inspection bound {MAX_MVCC_SNAP_READ_BYTES} (rebuildable)"
                )),
            );
            check.find(
                "projection_snapshot_oversize",
                DoctorSeverity::Info,
                None,
                None,
            );
        } else {
            match File::open(&snap_path) {
                Ok(file) => {
                    let regular_after_open = file
                        .metadata()
                        .map(|m| m.file_type().is_file())
                        .unwrap_or(false);
                    let mut bytes = Vec::new();
                    let read_ok = regular_after_open
                        && file
                            .take(MAX_MVCC_SNAP_READ_BYTES.saturating_add(1))
                            .read_to_end(&mut bytes)
                            .is_ok()
                        && (bytes.len() as u64) <= MAX_MVCC_SNAP_READ_BYTES;
                    if !read_ok {
                        check.field(
                            "reason",
                            text("derived mvcc.snap unreadable or exceeded bound during read (rebuildable)"),
                        );
                        check.find(
                            "projection_snapshot_unreadable",
                            DoctorSeverity::Info,
                            None,
                            None,
                        );
                    } else {
                        match ProjectionSnapshot::decode_snapshot_bytes(&bytes) {
                            Ok(snap) => {
                                snap_seq = snap.anchor.commit_sequence;
                                has_scrub_receipt |= snap.scrub_receipt.is_some();
                                check.field("snapshot_commit_sequence", num64(snap_seq));
                                check.evidence("snapshot_history_root", snap.anchor.history_root);
                            }
                            Err(err) => {
                                check.field(
                                    "reason",
                                    DoctorValue::String(format!(
                                        "derived mvcc.snap failed verification (rebuildable): {err}"
                                    )),
                                );
                                check.find(
                                    "projection_snapshot_corrupt",
                                    DoctorSeverity::Info,
                                    None,
                                    None,
                                );
                            }
                        }
                    }
                }
                Err(err) => {
                    check.field(
                        "reason",
                        DoctorValue::String(format!(
                            "derived mvcc.snap could not be opened (rebuildable): {err}"
                        )),
                    );
                    check.find(
                        "projection_snapshot_unreadable",
                        DoctorSeverity::Info,
                        None,
                        None,
                    );
                }
            }
        }
    }

    let mut wal_max_seq = 0_u64;
    if has_wal {
        match inspect_wal_readonly(&wal_path, MAX_MVCC_SNAP_READ_BYTES) {
            Ok(wal) => {
                wal_max_seq = wal.max_commit_sequence;
                has_scrub_receipt |= wal.latest_scrub_receipt.is_some();
                check.field("wal_batch_frames", num64(wal.batch_frames));
                check.field("wal_scrub_receipt_frames", num64(wal.scrub_receipt_frames));
                check.field("wal_max_commit_sequence", num64(wal_max_seq));
                check.field(
                    "wal_incomplete_tail",
                    DoctorValue::Bool(wal.incomplete_tail),
                );
                if wal.incomplete_tail {
                    check.find(
                        "projection_wal_incomplete_tail",
                        DoctorSeverity::Info,
                        None,
                        None,
                    );
                }
            }
            Err(err) => {
                check.field(
                    "wal_error",
                    DoctorValue::String(format!(
                        "derived mvcc.wal failed verification (rebuildable): {err}"
                    )),
                );
                check.find("projection_wal_corrupt", DoctorSeverity::Info, None, None);
            }
        }
    }

    check.field(
        "projected_commit_sequence",
        num64(snap_seq.max(wal_max_seq)),
    );
    check.field("has_scrub_receipt", DoctorValue::Bool(has_scrub_receipt));
    check
}
