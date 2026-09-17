#![forbid(unsafe_code)]
mod rtpdump_support;
use rtpdump_support::*;
use fss_core::{CanonicalEncode, CaptureInterval, ContentDigest, SensorId, StreamId, TimestampNs};
use fss_publication::SlotName;
use fss_reference::ReferenceDeployment;
use fss_reference::ingest::rtpdump::{import::*, recovery::*};

fn scope() -> Result<RtpImportScope, Error> {
    Ok(RtpImportScope { sensor: SensorId::parse("sensor:recovery")?,
        stream: StreamId::parse("stream:recovery")?, receive_time: TimestampNs(1_000_000_000) })
}
fn directory(label: &str) -> Result<std::path::PathBuf, Error> {
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(base)?;
    for i in 0..1000 {
        let path = base.join(format!("rtpdump-recovery-{label}-{}-{i}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => return Err(e.into()),
        }
    }
    Err("directory bound".into())
}
fn publish(bytes: &[u8], cx: &fss_reference::ReplayCx, dep: &mut ReferenceDeployment) -> Result<RtpFileImportReceipt, Error> {
    Ok(publish_rtp_import(prepare_rtp_import(bytes, scope()?, config(), RtpImportLimits::default(), cx)?, cx, dep)?)
}
/// Simulate loss of the importer after the existing publisher committed the root,
/// but before any capsule/terminal import batches were appended. Not a real kill test.
fn root_only(bytes: &[u8], cx: &fss_reference::ReplayCx, dep: &mut ReferenceDeployment) -> Result<ContentDigest, Error> {
    let plan = prepare_rtp_import(bytes, scope()?, config(), RtpImportLimits::default(), cx)?;
    for chunk in bytes.chunks(RtpImportLimits::default().chunk_bytes) { dep.stage_payload(chunk)?; }
    for (row, nal) in plan.report().nals().iter().zip(nals()) {
        dep.stage_payload(&bytes[row.source.clone()])?;
        dep.stage_payload(nal)?;
        dep.stage_payload(&row.capsule.try_canonical_bytes()?)?;
    }
    dep.stage_payload(plan.report_bytes())?;
    let root = plan.manifest().root();
    let hex: String = root.bytes().iter().map(|b| format!("{b:02x}")).collect();
    let slot = SlotName::parse(&format!("rtp-{hex}"))?;
    dep.publisher_mut().stage_manifest(&slot, plan.manifest())?;
    dep.publish_and_commit(&slot, plan.manifest(), CaptureInterval::new(TimestampNs(0), scope()?.receive_time)?, cx)?;
    Ok(root)
}

#[test]
fn complete_import_survives_loss_of_receipt_and_original_path() -> TestResult {
    let dir = directory("cold")?; let cx = cx()?; let bytes = real_dump(true);
    let mut dep = ReferenceDeployment::open(&dir, "site:rtp-recovery", &cx)?;
    let receipt = publish(&bytes, &cx, &mut dep)?;
    let root = receipt.root(); let anchor = receipt.anchor().clone();
    drop(receipt); drop(dep);
    let dep = ReferenceDeployment::reopen(&dir, "site:rtp-recovery", &cx)?;
    let before = dep.current_anchor().clone();
    let recovered = inspect_rtp_import(root, 999, RtpRecoveryPolicy::default(), &cx, &dep)?;
    assert_eq!(recovered.source(), bytes);
    assert_eq!(recovered.report().nals().len(), nals().len());
    assert_eq!(recovered.state(), &RtpRecoveryState::Complete { anchor });
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn root_only_publication_is_pending_until_explicit_idempotent_resume() -> TestResult {
    let dir = directory("pending")?; let cx = cx()?; let bytes = real_dump(false);
    let mut dep = ReferenceDeployment::open(&dir, "site:rtp-pending", &cx)?;
    let root = root_only(&bytes, &cx, &mut dep)?;
    let before = dep.current_anchor().clone(); let count = dep.ledger().batches().len();
    let recovered = inspect_rtp_import(root, 3, RtpRecoveryPolicy::default(), &cx, &dep)?;
    assert_eq!(recovered.state(), &RtpRecoveryState::LedgerPending { committed_capsules: 0, total_capsules: nals().len() });
    assert_eq!(dep.current_anchor(), &before); assert_eq!(dep.ledger().batches().len(), count);
    let receipt = recovered.resume(&cx, &mut dep)?;
    assert_eq!(receipt.root(), root);
    assert_eq!(load_rtp_import(&receipt, &cx, &dep)?.source(), bytes);
    let count = dep.ledger().batches().len();
    let recovered = inspect_rtp_import(root, 77, RtpRecoveryPolicy::default(), &cx, &dep)?;
    assert!(matches!(recovered.state(), RtpRecoveryState::Complete { .. }));
    let again = recovered.resume(&cx, &mut dep)?;
    assert_eq!(again.root(), root); assert_eq!(dep.ledger().batches().len(), count);
    Ok(())
}

#[test]
fn root_recovery_retains_a_malformed_tail_without_claiming_clean_media() -> TestResult {
    let dir = directory("tail")?; let cx = cx()?; let mut bytes = real_dump(false);
    bytes.extend_from_slice(&[0, 20, 0, 12]);
    let mut dep = ReferenceDeployment::open(&dir, "site:rtp-tail-recovery", &cx)?;
    let receipt = publish(&bytes, &cx, &mut dep)?;
    let root = receipt.root(); drop(receipt);
    let recovered = inspect_rtp_import(root, 10, RtpRecoveryPolicy::default(), &cx, &dep)?;
    assert_eq!(recovered.source(), bytes);
    assert!(matches!(recovered.report().end(), ImportEnd::FramingRefused(_)));
    assert!(recovered.report().nals().iter().all(|n| n.capsule.frame_count == 0));
    Ok(())
}

#[test]
fn recovery_policy_cannot_be_widened_by_stored_recipe() -> TestResult {
    let dir = directory("limits")?; let cx = cx()?; let bytes = real_dump(false);
    let mut dep = ReferenceDeployment::open(&dir, "site:rtp-limits-recovery", &cx)?;
    let root = publish(&bytes, &cx, &mut dep)?.root();
    for policy in [RtpRecoveryPolicy { max_source_bytes: 1, ..RtpRecoveryPolicy::default() },
        RtpRecoveryPolicy { max_records: 1, ..RtpRecoveryPolicy::default() },
        RtpRecoveryPolicy { import: RtpImportLimits { max_nals: 1, ..RtpImportLimits::default() }, ..RtpRecoveryPolicy::default() }] {
        assert!(matches!(inspect_rtp_import(root, 1, policy, &cx, &dep), Err(RtpImportError::Limit)));
    }
    assert!(matches!(inspect_rtp_import(root, 0, RtpRecoveryPolicy::default(), &cx, &dep), Err(RtpImportError::Binding)));
    Ok(())
}

#[test]
fn changed_anchor_requires_reinspection_before_resume() -> TestResult {
    let dir = directory("stale")?; let cx = cx()?; let bytes = real_dump(false);
    let mut dep = ReferenceDeployment::open(&dir, "site:rtp-stale-recovery", &cx)?;
    let root = root_only(&bytes, &cx, &mut dep)?;
    let recovered = inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep)?;
    // Even safe unrelated commits invalidate this prepared recovery's exact basis.
    publish(&real_dump(true), &cx, &mut dep)?;
    let before = dep.current_anchor().clone();
    assert!(matches!(recovered.resume(&cx, &mut dep), Err(RtpImportError::Binding)));
    assert_eq!(dep.current_anchor(), &before);
    Ok(())
}

#[test]
fn corruption_and_cancellation_cannot_produce_a_recovery_receipt() -> TestResult {
    use std::io::Write;
    let dir = directory("corrupt")?; let cx = cx()?; let bytes = real_dump(false);
    let mut dep = ReferenceDeployment::open(&dir, "site:rtp-corrupt-recovery", &cx)?;
    let receipt = publish(&bytes, &cx, &mut dep)?;
    let root = receipt.root();
    let path = dep.publisher().spool().object_path(receipt.report().nals()[0].digest);
    let mut file = std::fs::OpenOptions::new().append(true).open(path)?;
    file.write_all(&[0xff])?; file.sync_all()?; drop(file);
    let before = dep.current_anchor().clone();
    assert!(inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep).is_err());
    assert_eq!(dep.current_anchor(), &before);
    cx.request_cancellation();
    assert!(matches!(inspect_rtp_import(root, 1, RtpRecoveryPolicy::default(), &cx, &dep), Err(RtpImportError::Cancelled)));
    Ok(())
}
