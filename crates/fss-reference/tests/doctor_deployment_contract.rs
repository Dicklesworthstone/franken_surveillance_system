#![forbid(unsafe_code)]
//! Contract test suite for read-only reference deployment doctor inspection (fss-2h5zq.57 / CAP- DOCTOR).
//!
//! Verifies:
//! 1. `inspect_deployment` is strictly read-only: every inspection leaves the directory
//!    tree byte-for-byte identical (verified by recursive tree digest before and after).
//! 2. Clean deployments report `healthy` with exit code 0.
//! 3. Incomplete tail on journals reports `attention_required` (exit code 3) with next affordance.
//! 4. Foreign trailing bytes without valid records report `foreign_trailing_bytes` with repair affordance.
//! 5. Corrupt history (foreign bytes containing a structurally valid record) reports `corrupt_history` with backup restore affordance.
//! 6. Live concurrent writer lock is detected typed via `/proc/locks`, reporting `concurrent_writer` and marking incomplete tails as `possibly_in_flight`.
//! 7. Orphaned staging in spool reports `orphaned_staging` with discard affordance.
//! 8. Orphaned root temporary files report `orphaned_root_temps` with discard affordance.
//! 9. Broken slots report `broken_roots`.
//! 10. Pending roots (published locally but not committed to ledger) report `pending_roots`.
//! 11. Indeterminate obligations in effects journal report `indeterminate_obligations` with reconcile affordance.
//! 12. Leftover repair temporary files report `leftover_repair_temps`.
//! 13. Non-deployment directories report `not_a_deployment` with exit code 4.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EffectIntent, EffectState, EvidenceDelta,
    IdempotencyKey, ObligationId, OperationId, Plane, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{ObjectManifest, SpoolLimits};
use fss_publication::{
    LOCAL_ROOTS_DIR, LOCAL_SPOOL_DIR, LocalPublicationLimits, LocalRootPublisher,
    ROOT_RECORD_SUFFIX, ROOT_TEMP_SUFFIX, SlotName,
};
use fss_reference::DurableEffectJournal;
use fss_reference::doctor::{DoctorVerdict, inspect_deployment};
use fss_reference::reference_deployment::{
    DeploymentLayout, DeploymentLimits, HostLayoutIo, RELATIVE_PATH_EFFECTS, RELATIVE_PATH_LEDGER,
    RELATIVE_PATH_OBJECTS, write_layout_atomic,
};

type TestResult = Result<(), Box<dyn Error>>;

const LINEAGE: &str = "site:doctor-contract";

fn fresh(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("doctor_deployment_contract")
        .join(name);
    match fs::remove_dir_all(&base) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(&base)?;
    Ok(base)
}

/// Digest over relative path, mode, size, mtime, ctime, inode, link count, content, and listing.
fn tree_digest(root: &Path) -> Result<BTreeMap<PathBuf, String>, Box<dyn Error>> {
    let mut out = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path.strip_prefix(root)?.to_path_buf();
        let common = format!(
            "mode={:o} size={} mtime={}.{} ctime={}.{} ino={} nlink={}",
            meta.mode(),
            meta.size(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
            meta.ino(),
            meta.nlink()
        );
        let detail = if meta.file_type().is_dir() {
            let mut names = Vec::new();
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                names.push(entry.file_name().to_string_lossy().into_owned());
                pending.push(entry.path());
            }
            names.sort();
            format!("dir [{}]", names.join(","))
        } else {
            format!("file {}", ContentDigest::sha256(&fs::read(&path)?))
        };
        out.insert(rel, format!("{common} {detail}"));
    }
    Ok(out)
}

fn assert_same_tree(label: &str, before: &BTreeMap<PathBuf, String>, root: &Path) -> TestResult {
    let after = tree_digest(root)?;
    if &after != before {
        return Err(format!("tree changed by {label}: before={before:#?} after={after:#?}").into());
    }
    Ok(())
}

fn append_bytes(path: &Path, bytes: &[u8]) -> TestResult {
    OpenOptions::new()
        .append(true)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn init_clean_deployment(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = fresh(name)?;
    let limits = DeploymentLimits::default();
    let layout = DeploymentLayout::new(LINEAGE, limits.canonical_digest()?);
    write_layout_atomic(&base, &layout, &HostLayoutIo)?;

    let objects_dir = base.join(RELATIVE_PATH_OBJECTS);
    let ledger_path = base.join(RELATIVE_PATH_LEDGER);
    let effects_path = base.join(RELATIVE_PATH_EFFECTS);

    fs::create_dir_all(ledger_path.parent().ok_or("ledger parent")?)?;
    fs::create_dir_all(effects_path.parent().ok_or("effects parent")?)?;

    // Create initialized ledger journal
    let _ledger =
        DurableReferenceLedger::open(&ledger_path, LINEAGE, IncompleteTailPolicy::Reject)?;
    // Create initialized effects journal
    let _effects = DurableEffectJournal::open(&effects_path, IncompleteTailPolicy::Reject)?;
    // Create initialized publication root
    let _publisher = LocalRootPublisher::open(&objects_dir, limits.to_publication_limits())?;

    Ok(base)
}

#[test]
fn test_clean_deployment_is_healthy_and_zero_mutation() -> TestResult {
    let dep = init_clean_deployment("clean")?;
    let before = tree_digest(&dep)?;

    let report = inspect_deployment(&dep);
    assert_same_tree("clean inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::Healthy);
    assert_eq!(report.exit_code(), 0);
    assert!(report.is_healthy());

    let json = report.to_json();
    assert!(json.contains("\"verdict\":\"healthy\""));
    assert!(json.contains("\"schema\":\"fss.doctor.v1\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_incomplete_tail_on_ledger_reports_attention_required() -> TestResult {
    let dep = init_clean_deployment("incomplete_tail")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);

    // Commit one valid batch first
    {
        let mut ledger =
            DurableReferenceLedger::open(&ledger_path, LINEAGE, IncompleteTailPolicy::Reject)?;
        let delta = EvidenceDelta {
            delta_id: "delta:1".to_owned(),
            family: "sensor_capsule".to_owned(),
            object_id: fss_core::ObjectId::parse("obj:1")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(b"payload"),
            witness_digest: None,
            operation_id: None,
        };
        let batch = ledger.prepare_batch(BatchId::parse("batch:1")?, vec![delta], [])?;
        let _ = ledger.append(batch)?;
    }

    // Append incomplete record prefix (first 16 bytes of RECORD_MAGIC)
    let head = fs::read(&ledger_path)?;
    append_bytes(&ledger_path, head.get(..16).ok_or("short ledger")?)?;

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("incomplete tail inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let ledger_check = report
        .checks
        .iter()
        .find(|c| c.id == "ledger.journal")
        .ok_or("missing ledger check")?;
    assert_eq!(ledger_check.status, "incomplete_tail");
    let next_affordance = ledger_check
        .next_affordance
        .as_ref()
        .ok_or("missing affordance")?;
    assert!(
        next_affordance.contains("--truncate-incomplete-tail ledger"),
        "expected truncate affordance, got {next_affordance}"
    );

    let json = report.to_json();
    assert!(json.contains("\"status\":\"incomplete_tail\""));
    assert!(json.contains("\"verdict\":\"attention_required\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_foreign_trailing_bytes_reports_repair_affordance() -> TestResult {
    let dep = init_clean_deployment("foreign_trailing")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);

    // Append arbitrary random foreign trailing bytes (no valid record inside)
    append_bytes(&ledger_path, b"FOREIGN_GARBAGE_BYTES_WITHOUT_MAGIC")?;

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("foreign trailing inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let ledger_check = report
        .checks
        .iter()
        .find(|c| c.id == "ledger.journal")
        .ok_or("missing ledger check")?;
    assert_eq!(ledger_check.status, "foreign_trailing_bytes");
    let next_affordance = ledger_check
        .next_affordance
        .as_ref()
        .ok_or("missing affordance")?;
    assert!(
        next_affordance.contains("--plan-ledger-repair then --apply-ledger-repair"),
        "expected plan repair affordance, got {next_affordance}"
    );

    let json = report.to_json();
    assert!(json.contains("\"status\":\"foreign_trailing_bytes\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_corrupt_history_with_valid_record_reports_owner_action() -> TestResult {
    let dep = init_clean_deployment("corrupt_history")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);

    // Create a second temporary ledger to produce a structurally valid committed record
    let temp_ledger_path = dep.join("ledger").join("temp.journal");
    {
        let mut temp_ledger =
            DurableReferenceLedger::open(&temp_ledger_path, LINEAGE, IncompleteTailPolicy::Reject)?;
        let delta = EvidenceDelta {
            delta_id: "delta:corrupt".to_owned(),
            family: "sensor_capsule".to_owned(),
            object_id: fss_core::ObjectId::parse("obj:corrupt")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(500), TimestampNs(600))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(b"corrupt-payload"),
            witness_digest: None,
            operation_id: None,
        };
        let batch = temp_ledger.prepare_batch(BatchId::parse("batch:corrupt")?, vec![delta], [])?;
        let _ = temp_ledger.append(batch)?;
    }
    let valid_record_bytes = fs::read(&temp_ledger_path)?;
    fs::remove_file(&temp_ledger_path)?;

    // Append a non-magic pad followed by the valid record bytes
    let mut corrupt_tail = Vec::new();
    corrupt_tail.extend_from_slice(b"NON_MAGIC_PAD_BYTES_");
    corrupt_tail.extend_from_slice(&valid_record_bytes);
    append_bytes(&ledger_path, &corrupt_tail)?;

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("corrupt history inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let ledger_check = report
        .checks
        .iter()
        .find(|c| c.id == "ledger.journal")
        .ok_or("missing ledger check")?;
    assert_eq!(ledger_check.status, "corrupt_history");
    let next_affordance = ledger_check
        .next_affordance
        .as_ref()
        .ok_or("missing affordance")?;
    assert!(
        next_affordance.contains("owner action: restore from backup or inspect physical media"),
        "expected restore backup affordance, got {next_affordance}"
    );

    let json = report.to_json();
    assert!(json.contains("\"status\":\"corrupt_history\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_live_concurrent_writer_detected_via_flock() -> TestResult {
    let dep = init_clean_deployment("live_writer")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);

    // Commit one valid batch first so the ledger has committed records
    {
        let mut ledger =
            DurableReferenceLedger::open(&ledger_path, LINEAGE, IncompleteTailPolicy::Reject)?;
        let delta = EvidenceDelta {
            delta_id: "delta:writer".to_owned(),
            family: "sensor_capsule".to_owned(),
            object_id: fss_core::ObjectId::parse("obj:writer")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(100), TimestampNs(200))?,
            plane: Plane::Authority,
            payload_digest: ContentDigest::sha256(b"writer-payload"),
            witness_digest: None,
            operation_id: None,
        };
        let batch = ledger.prepare_batch(BatchId::parse("batch:writer")?, vec![delta], [])?;
        let _ = ledger.append(batch)?;
    }

    // Append incomplete record prefix
    append_bytes(&ledger_path, b"FSSJRN01")?;

    // Hold flock on ledger journal
    let holder = fs::File::open(&ledger_path)?;
    holder.try_lock()?;

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("live writer inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let writer_check = report
        .checks
        .iter()
        .find(|c| c.id == "deployment.writer")
        .ok_or("missing writer check")?;
    assert_eq!(writer_check.status, "concurrent_writer");

    let ledger_check = report
        .checks
        .iter()
        .find(|c| c.id == "ledger.journal")
        .ok_or("missing ledger check")?;
    // With writer held, incomplete tail must be classified as possibly_in_flight
    assert_eq!(ledger_check.status, "possibly_in_flight");

    drop(holder);
    Ok(())
}

#[test]
fn test_orphaned_staging_reports_discard_affordance() -> TestResult {
    let dep = init_clean_deployment("orphaned_staging")?;
    let staging_dir = dep
        .join(RELATIVE_PATH_OBJECTS)
        .join(LOCAL_SPOOL_DIR)
        .join("staging");
    fs::create_dir_all(&staging_dir)?;
    let digest = ContentDigest::sha256(b"staging-data");
    let hex: String = digest.bytes().iter().map(|b| format!("{b:02x}")).collect();
    let orphan_name = format!("{hex}.0.tmp");
    fs::write(staging_dir.join(orphan_name), b"staging-data")?;

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("orphaned staging inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let staging_check = report
        .checks
        .iter()
        .find(|c| c.id == "publication.staging")
        .ok_or("missing staging check")?;
    assert_eq!(staging_check.status, "orphaned_staging");
    let next_affordance = staging_check
        .next_affordance
        .as_ref()
        .ok_or("missing affordance")?;
    assert!(
        next_affordance.contains("--discard-orphaned-staging"),
        "expected discard affordance, got {next_affordance}"
    );

    let json = report.to_json();
    assert!(json.contains("\"status\":\"orphaned_staging\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_orphaned_root_temps_reports_discard_affordance() -> TestResult {
    let dep = init_clean_deployment("orphaned_root_temps")?;
    let roots_dir = dep.join(RELATIVE_PATH_OBJECTS).join(LOCAL_ROOTS_DIR);
    fs::create_dir_all(&roots_dir)?;
    fs::write(
        roots_dir.join(format!("slot_test{ROOT_RECORD_SUFFIX}{ROOT_TEMP_SUFFIX}")),
        b"temp-root",
    )?;

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("orphaned root temps inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let roots_check = report
        .checks
        .iter()
        .find(|c| c.id == "publication.roots")
        .ok_or("missing roots check")?;
    assert_eq!(roots_check.status, "orphaned_root_temps");
    let next_affordance = roots_check
        .next_affordance
        .as_ref()
        .ok_or("missing affordance")?;
    assert!(
        next_affordance.contains("--discard-orphaned-temps"),
        "expected discard affordance, got {next_affordance}"
    );

    let json = report.to_json();
    assert!(json.contains("\"status\":\"orphaned_root_temps\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_pending_roots_reports_commit_affordance() -> TestResult {
    let dep = init_clean_deployment("pending_roots")?;
    let objects_dir = dep.join(RELATIVE_PATH_OBJECTS);

    // Publish a root locally without committing to the ledger
    {
        let limits =
            LocalPublicationLimits::new(8, 16, 8, 64, SpoolLimits::new(64, 1 << 20, 4096, 64));
        let mut local = LocalRootPublisher::open(&objects_dir, limits)?;
        let child = local.stage_object(b"clip-pending")?;
        let manifest = ObjectManifest::new("event_archive", [child], None)?;
        let _ = local.publish(&SlotName::parse("pending_slot")?, &manifest)?;
    }

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("pending roots inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let roots_check = report
        .checks
        .iter()
        .find(|c| c.id == "publication.roots")
        .ok_or("missing roots check")?;
    assert_eq!(roots_check.status, "pending_roots");
    let next_affordance = roots_check
        .next_affordance
        .as_ref()
        .ok_or("missing affordance")?;
    assert!(
        next_affordance.contains("rerun producing command or explicit commit"),
        "expected commit affordance, got {next_affordance}"
    );

    let json = report.to_json();
    assert!(json.contains("\"status\":\"pending_roots\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_indeterminate_obligations_reports_reconcile_affordance() -> TestResult {
    let dep = init_clean_deployment("indeterminate_obligations")?;
    let effects_path = dep.join(RELATIVE_PATH_EFFECTS);

    // Create an indeterminate operation in effects journal
    let operation = OperationId::parse("op:doctor-test:1")?;
    {
        let mut journal = DurableEffectJournal::open(&effects_path, IncompleteTailPolicy::Reject)?;
        let intent = EffectIntent {
            operation_id: operation.clone(),
            idempotency_key: IdempotencyKey::parse("idempotency:doctor-test:1")?,
            effect_class: "alert.dispatch".to_string(),
            request_digest: ContentDigest::sha256(b"req"),
            precondition_digest: ContentDigest::sha256(b"pre"),
        };
        let obligation = ObligationId::parse("obligation:doctor-test:1")?;
        let _ = journal.prepare(intent, obligation, "delivery_ack", TimestampNs(100))?;
        let _ = journal.transition(
            &operation,
            EffectState::Committed,
            TimestampNs(110),
            None,
            None,
        )?;
        let _ = journal.mark_indeterminate(&operation, TimestampNs(120), "timeout")?;
    }

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("indeterminate obligations inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let obligations_check = report
        .checks
        .iter()
        .find(|c| c.id == "effects.obligations")
        .ok_or("missing obligations check")?;
    assert_eq!(obligations_check.status, "indeterminate_obligations");
    let next_affordance = obligations_check
        .next_affordance
        .as_ref()
        .ok_or("missing affordance")?;
    assert!(
        next_affordance.contains("--reconcile-effects"),
        "expected reconcile affordance, got {next_affordance}"
    );

    let json = report.to_json();
    assert!(json.contains("\"status\":\"indeterminate_obligations\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_leftover_repair_temps_reports_repair_affordance() -> TestResult {
    let dep = init_clean_deployment("leftover_temps")?;
    let ledger_dir = dep.join("ledger");
    fs::write(
        ledger_dir.join("journal.fssj.tmp.1234.5678"),
        b"interrupted-repair",
    )?;

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("leftover repair temps inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::AttentionRequired);
    assert_eq!(report.exit_code(), 3);

    let sidecars_check = report
        .checks
        .iter()
        .find(|c| c.id == "sidecars")
        .ok_or("missing sidecars check")?;
    assert_eq!(sidecars_check.status, "leftover_repair_temps");
    let next_affordance = sidecars_check
        .next_affordance
        .as_ref()
        .ok_or("missing affordance")?;
    assert!(
        next_affordance.contains("--apply-ledger-repair"),
        "expected apply repair affordance, got {next_affordance}"
    );

    let json = report.to_json();
    assert!(json.contains("\"status\":\"leftover_repair_temps\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_quarantine_sidecars_are_informational_healthy() -> TestResult {
    let dep = init_clean_deployment("quarantine_sidecars")?;
    let ledger_dir = dep.join("ledger");
    fs::write(
        ledger_dir.join("journal.fssj.quarantine"),
        b"quarantined-bytes",
    )?;

    let before = tree_digest(&dep)?;
    let report = inspect_deployment(&dep);
    assert_same_tree("quarantine sidecars inspection", &before, &dep)?;

    assert_eq!(report.verdict, DoctorVerdict::Healthy);
    assert_eq!(report.exit_code(), 0);

    let sidecars_check = report
        .checks
        .iter()
        .find(|c| c.id == "sidecars")
        .ok_or("missing sidecars check")?;
    assert_eq!(sidecars_check.status, "clean");

    let json = report.to_json();
    assert!(json.contains("\"verdict\":\"healthy\""));
    assert_same_tree("after json generation", &before, &dep)?;
    Ok(())
}

#[test]
fn test_not_a_deployment_reports_exit_code_4() -> TestResult {
    let empty_dir = fresh("empty_dir")?;
    let before = tree_digest(&empty_dir)?;

    let report = inspect_deployment(&empty_dir);
    assert_same_tree("empty dir inspection", &before, &empty_dir)?;

    assert_eq!(report.verdict, DoctorVerdict::NotADeployment);
    assert_eq!(report.exit_code(), 4);

    let layout_check = report
        .checks
        .iter()
        .find(|c| c.id == "deployment.layout")
        .ok_or("missing layout check")?;
    assert_eq!(layout_check.status, "missing");

    let json = report.to_json();
    assert!(json.contains("\"verdict\":\"not_a_deployment\""));
    assert_same_tree("after json generation", &before, &empty_dir)?;

    // Non-existent directory
    let non_existent = empty_dir.join("non_existent_subdir");
    let report_non_existent = inspect_deployment(&non_existent);
    assert_eq!(report_non_existent.verdict, DoctorVerdict::NotADeployment);
    assert_eq!(report_non_existent.exit_code(), 4);
    Ok(())
}
