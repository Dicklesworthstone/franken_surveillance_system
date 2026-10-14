#![forbid(unsafe_code)]
//! Real retained-RTP source lifecycle through the existing graph-complete deletion owner.
//! Tests use fixture recordings only. Cancellation is an injected cut, not a power-loss claim.
mod rtpdump_support;

use fss_core::{CanonicalEncode, CaptureInterval, ContentDigest, SensorId, StreamId, TimestampNs};
use fss_publication::SlotName;
use fss_reference::deletion::{
    CommitOutcome, DeletionError, DeletionIndex, DeletionScope, STAGE_DELETION_RECORD_APPENDED,
    commit_deletion, plan_deletion, plan_scope_deletion,
};
use fss_reference::ingest::rtpdump::import::{
    RtpFileImportReceipt, RtpImportError, RtpImportLimits, RtpImportScope, load_rtp_import,
    prepare_rtp_import, publish_rtp_import,
};
use fss_reference::ingest::rtpdump::recovery::{RtpRecoveryPolicy, inspect_rtp_import};
use fss_reference::{ReferenceDeployment, ReplayCx};
use rtpdump_support::*;
use std::path::PathBuf;

const SITE: &str = "site:rtp-deletion";
const PRINCIPAL: &str = "operator:rtp-deletion";
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Result<Self, Error> {
        let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(base)?;
        for at in 0..1000 {
            let path = base.join(format!("rtp-deletion-{label}-{}-{at}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("temporary directory limit".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn scope(sensor: &str) -> Result<RtpImportScope, Error> {
    Ok(RtpImportScope {
        sensor: SensorId::parse(format!("sensor:{sensor}"))?,
        stream: StreamId::parse(format!("stream:{sensor}"))?,
        receive_time: TimestampNs(1_000_000_000),
    })
}
fn publish(
    bytes: &[u8],
    sensor: &str,
    dep: &mut ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<RtpFileImportReceipt, Error> {
    Ok(publish_rtp_import(
        prepare_rtp_import(
            bytes,
            scope(sensor)?,
            config(),
            RtpImportLimits::default(),
            cx,
        )?,
        cx,
        dep,
    )?)
}
fn assert_deleted<T>(
    result: Result<T, RtpImportError>,
    root: ContentDigest,
    plan: ContentDigest,
) -> TestResult {
    match result {
        Err(RtpImportError::EvidenceDeleted { root: r, plan: p }) => {
            assert_eq!((r, p), (root, plan));
            Ok(())
        }
        Err(error) => Err(format!("wrong denial: {error}").into()),
        Ok(_) => Err("deleted recording was served or republished".into()),
    }
}

#[test]
fn complete_rtp_deletion_is_read_only_until_approved_and_survives_cold_reopen() -> TestResult {
    let dir = Directory::new("complete")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let bytes = real_dump(true);
    let receipt = publish(&bytes, "north", &mut dep, &context)?;
    let root = receipt.root();
    let before = dep.current_anchor().clone();
    let objects = dep.publisher().spool().object_count();
    let plan = plan_deletion(&dep, root, &context)?;
    assert_eq!(dep.current_anchor(), &before);
    assert_eq!(dep.publisher().spool().object_count(), objects);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert_eq!(plan.imports, [root]);
    assert!(plan.deletable.iter().any(|object| object.digest == root));
    assert!(
        plan.units
            .iter()
            .any(|unit| unit.id.starts_with("batch:rtp:") && unit.kind == "import_custody")
    );
    assert!(
        plan.retractions
            .iter()
            .any(|row| row.slot == receipt.slot().as_str())
    );
    assert!(
        plan.tombstones
            .iter()
            .any(|row| row.object_id.starts_with("object:rtp:"))
    );
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    commit_deletion(&mut dep, digest, approval, PRINCIPAL, &context)?;
    for object in &plan.deletable {
        assert!(!dep.publisher().spool().object_path(object.digest).exists());
    }
    assert_deleted(load_rtp_import(&receipt, &context, &dep), root, digest)?;
    drop(dep);
    let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &context)?;
    assert_deleted(
        inspect_rtp_import(root, 2, RtpRecoveryPolicy::default(), &context, &dep),
        root,
        digest,
    )?;
    let head = dep.current_anchor().clone();
    let again = commit_deletion(&mut dep, digest, approval, PRINCIPAL, &context)?;
    assert_eq!(again.outcome, CommitOutcome::AlreadyComplete);
    assert_eq!(dep.current_anchor(), &head);
    assert!(
        DeletionIndex::read(&dep)?
            .import(root)
            .is_some_and(|entry| entry.is_complete())
    );
    Ok(())
}

#[test]
fn durable_denial_precedes_unlink_and_fences_read_resume_and_republication() -> TestResult {
    let dir = Directory::new("cut")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let bytes = real_dump(false);
    let receipt = publish(&bytes, "north", &mut dep, &context)?;
    let root = receipt.root();
    let recovered = inspect_rtp_import(root, 2, RtpRecoveryPolicy::default(), &context, &dep)?;
    let prepared = prepare_rtp_import(
        &bytes,
        scope("north")?,
        config(),
        RtpImportLimits::default(),
        &context,
    )?;
    let plan = plan_deletion(&dep, root, &context)?;
    let digest = plan.digest()?;
    let approval = plan.approval_digest(PRINCIPAL)?;
    let stop = cx()?;
    stop.set_cancel_at_checkpoint(STAGE_DELETION_RECORD_APPENDED);
    assert!(matches!(
        commit_deletion(&mut dep, digest, approval, PRINCIPAL, &stop),
        Err(DeletionError::Cancelled {
            stage: STAGE_DELETION_RECORD_APPENDED
        })
    ));
    assert!(
        plan.deletable.iter().all(|object| dep
            .publisher()
            .spool()
            .object_path(object.digest)
            .exists())
    );
    let head = dep.current_anchor().clone();
    let objects = dep.publisher().spool().object_count();
    assert_deleted(load_rtp_import(&receipt, &context, &dep), root, digest)?;
    assert_deleted(
        inspect_rtp_import(root, 3, RtpRecoveryPolicy::default(), &context, &dep),
        root,
        digest,
    )?;
    assert_deleted(recovered.resume(&context, &mut dep), root, digest)?;
    assert_deleted(
        publish_rtp_import(prepared, &context, &mut dep),
        root,
        digest,
    )?;
    assert_eq!(dep.current_anchor(), &head);
    assert_eq!(dep.publisher().spool().object_count(), objects);
    drop(dep);
    let mut dep = ReferenceDeployment::reopen(&dir.0, SITE, &context)?;
    assert_deleted(load_rtp_import(&receipt, &context, &dep), root, digest)?;
    commit_deletion(&mut dep, digest, approval, PRINCIPAL, &context)?;
    assert!(
        DeletionIndex::read(&dep)?
            .import(root)
            .is_some_and(|entry| entry.is_complete())
    );
    Ok(())
}

#[test]
fn shared_source_objects_and_other_rtp_import_remain_readable() -> TestResult {
    let dir = Directory::new("shared")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let bytes = real_dump(true);
    let first = publish(&bytes, "north", &mut dep, &context)?;
    let second = publish(&bytes, "south", &mut dep, &context)?;
    assert_ne!(first.root(), second.root());
    let shared = first.report().chunk_digests()[0];
    assert!(second.report().chunk_digests().contains(&shared));
    let plan = plan_deletion(&dep, first.root(), &context)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert!(!plan.deleted_set().contains(&shared));
    assert!(!plan.deleted_set().contains(&second.root()));
    commit_deletion(
        &mut dep,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    assert_eq!(load_rtp_import(&second, &context, &dep)?.source(), bytes);
    let plan = plan_deletion(&dep, second.root(), &context)?;
    assert!(plan.deleted_set().contains(&shared));
    commit_deletion(
        &mut dep,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    assert!(!dep.publisher().spool().object_path(shared).exists());
    Ok(())
}

#[test]
fn sensor_scope_includes_capsuleless_rtp_and_preserves_other_sensor() -> TestResult {
    let dir = Directory::new("sensors")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let first = publish(&header(), "north", &mut dep, &context)?;
    assert!(first.report().access_units().is_empty());
    let second = publish(&real_dump(false), "north", &mut dep, &context)?;
    let other = publish(&real_dump(true), "south", &mut dep, &context)?;
    let scope = DeletionScope::Sensor(SensorId::parse("sensor:north")?);
    let plan = plan_scope_deletion(&dep, &scope, &context)?;
    let mut expected = vec![first.root(), second.root()];
    expected.sort();
    assert_eq!(plan.imports, expected);
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    assert_eq!(
        plan.validity,
        CaptureInterval::new(TimestampNs(0), TimestampNs(1_000_000_000))?
    );
    let digest = plan.digest()?;
    commit_deletion(
        &mut dep,
        digest,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    assert_deleted(
        load_rtp_import(&first, &context, &dep),
        first.root(),
        digest,
    )?;
    assert_deleted(
        load_rtp_import(&second, &context, &dep),
        second.root(),
        digest,
    )?;
    load_rtp_import(&other, &context, &dep)?;
    Ok(())
}

#[test]
fn root_only_publication_never_becomes_a_completed_lifecycle_import() -> TestResult {
    let dir = Directory::new("pending")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let bytes = real_dump(false);
    let plan = prepare_rtp_import(
        &bytes,
        scope("north")?,
        config(),
        RtpImportLimits::default(),
        &context,
    )?;
    for chunk in bytes.chunks(RtpImportLimits::default().chunk_bytes) {
        dep.stage_payload(chunk)?;
    }
    for nal in nals() {
        dep.stage_payload(nal)?;
    }
    for unit in plan.report().access_units() {
        dep.stage_payload(&bytes[unit.source.clone()])?;
        dep.stage_payload(&unit.capsule.try_canonical_bytes()?)?;
    }
    dep.stage_payload(plan.report_bytes())?;
    let root = plan.manifest().root();
    let hex: String = root
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let slot = SlotName::parse(&format!("rtp-{hex}"))?;
    dep.publisher_mut().stage_manifest(&slot, plan.manifest())?;
    dep.publish_and_commit(
        &slot,
        plan.manifest(),
        CaptureInterval::new(TimestampNs(0), scope("north")?.receive_time)?,
        &context,
    )?;
    let head = dep.current_anchor().clone();
    assert!(
        matches!(plan_deletion(&dep, root, &context), Err(DeletionError::UnknownImport(value)) if value == root)
    );
    assert_eq!(dep.current_anchor(), &head);
    Ok(())
}

#[test]
fn deleted_source_cannot_be_resurrected_under_a_new_sensor_identity() -> TestResult {
    let dir = Directory::new("resurrect")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let bytes = real_dump(false);
    let first = publish(&bytes, "north", &mut dep, &context)?;
    let plan = plan_deletion(&dep, first.root(), &context)?;
    let digest = plan.digest()?;
    commit_deletion(
        &mut dep,
        digest,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    let head = dep.current_anchor().clone();
    let objects = dep.publisher().spool().object_count();
    let prepared = prepare_rtp_import(
        &bytes,
        scope("south")?,
        config(),
        RtpImportLimits::default(),
        &context,
    )?;
    let new_root = prepared.manifest().root();
    assert_ne!(new_root, first.root());
    assert_deleted(
        publish_rtp_import(prepared, &context, &mut dep),
        new_root,
        digest,
    )?;
    assert_eq!(dep.current_anchor(), &head);
    assert_eq!(dep.publisher().spool().object_count(), objects);
    Ok(())
}

#[test]
fn malformed_tail_is_deletable_custody_not_an_undeletable_decode_failure() -> TestResult {
    let dir = Directory::new("tail")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 10, 0]);
    let receipt = publish(&bytes, "north", &mut dep, &context)?;
    let plan = plan_deletion(&dep, receipt.root(), &context)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let digest = plan.digest()?;
    commit_deletion(
        &mut dep,
        digest,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    assert_deleted(
        load_rtp_import(&receipt, &context, &dep),
        receipt.root(),
        digest,
    )?;
    Ok(())
}

#[test]
fn unrelated_prefixed_batch_is_not_a_deletion_seed() -> TestResult {
    use fss_core::{BatchId, EvidenceDelta, ObjectId, Plane};
    let dir = Directory::new("extra-batch")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let receipt = publish(&real_dump(false), "north", &mut dep, &context)?;
    let root = receipt.root();
    let hex: String = root
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let id = format!("batch:rtp:{hex}:c999");
    let payload = dep.stage_payload(b"unrelated retained content")?;
    dep.append_batch(
        BatchId::parse(&id)?,
        vec![EvidenceDelta {
            delta_id: "delta:extra-content".into(),
            family: "test_content".into(),
            object_id: ObjectId::parse("object:extra-content")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            plane: Plane::Authority,
            payload_digest: payload,
            witness_digest: None,
            operation_id: None,
        }],
        vec![payload],
        &context,
    )?;
    let plan = plan_deletion(&dep, root, &context)?;
    assert!(!plan.units.iter().any(|unit| unit.id == id));
    assert!(!plan.deleted_set().contains(&payload));
    commit_deletion(
        &mut dep,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    assert_eq!(
        dep.publisher().spool().read(payload)?,
        b"unrelated retained content"
    );
    Ok(())
}

#[test]
fn corrupt_source_refuses_deletion_planning_without_unlinking() -> TestResult {
    let dir = Directory::new("corrupt")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let receipt = publish(&real_dump(false), "north", &mut dep, &context)?;
    let before = dep.current_anchor().clone();
    let objects = dep.publisher().spool().object_count();
    let target = dep
        .publisher()
        .spool()
        .object_path(receipt.report().chunk_digests()[0]);
    let mut bytes = std::fs::read(&target)?;
    *bytes.last_mut().ok_or("empty object")? ^= 1;
    std::fs::write(&target, &bytes)?;
    assert!(plan_deletion(&dep, receipt.root(), &context).is_err());
    assert_eq!(dep.current_anchor(), &before);
    assert_eq!(dep.publisher().spool().object_count(), objects);
    assert_eq!(std::fs::read(&target)?, bytes);
    Ok(())
}

#[test]
fn completed_import_name_is_not_sufficient_authority() -> TestResult {
    use fss_core::{BatchId, EvidenceDelta, ObjectId, Plane};
    let dir = Directory::new("forged-terminal")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let root = ContentDigest::sha256(b"not a retained import");
    let hex: String = root
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let payload = dep.stage_payload(b"no source graph or publication")?;
    dep.append_batch(
        BatchId::parse(format!("batch:rtp:{hex}"))?,
        vec![EvidenceDelta {
            delta_id: "delta:forged-terminal".into(),
            family: "test_content".into(),
            object_id: ObjectId::parse("object:forged-terminal")?,
            prior_generation: None,
            new_generation: 1,
            validity: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            plane: Plane::Authority,
            payload_digest: payload,
            witness_digest: None,
            operation_id: None,
        }],
        vec![payload],
        &context,
    )?;
    let before = dep.current_anchor().clone();
    assert!(matches!(
        plan_deletion(&dep, root, &context),
        Err(DeletionError::RecordMismatch)
    ));
    assert_eq!(dep.current_anchor(), &before);
    assert!(dep.publisher().spool().object_path(payload).exists());
    Ok(())
}

#[test]
fn deletion_fences_already_queued_snapshot_pixels() -> TestResult {
    use fss_reference::ingest::rtpdump::recovery::decode::{
        RetainedRtpDecodeRequest, RetainedRtpDecodeStep,
    };
    let dir = Directory::new("queued")?;
    let context = cx()?;
    let mut dep = ReferenceDeployment::open(&dir.0, SITE, &context)?;
    let receipt = publish(&real_dump(false), "north", &mut dep, &context)?;
    let retained = inspect_rtp_import(
        receipt.root(),
        2,
        RtpRecoveryPolicy::default(),
        &context,
        &dep,
    )?;
    let pair = retained
        .h264_parameters(&context)?
        .unique_pair()
        .ok_or("exact parameters")?;
    let mut decoder = retained.decode_h264(RetainedRtpDecodeRequest::new(pair), &dep, &context)?;
    for _ in 0..10_000 {
        decoder.step(&dep, &context)?;
        if decoder.queued_pictures() > 0 {
            break;
        }
    }
    assert!(decoder.queued_pictures() > 0);
    let delivered = decoder.stats().frames;
    let plan = plan_deletion(&dep, receipt.root(), &context)?;
    commit_deletion(
        &mut dep,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &context,
    )?;
    assert!(decoder.step(&dep, &context).is_err());
    assert_eq!(decoder.queued_pictures(), 0);
    assert_eq!(decoder.stats().frames, delivered);
    assert!(matches!(
        decoder.step(&dep, &context)?,
        RetainedRtpDecodeStep::Ended(_)
    ));
    Ok(())
}
