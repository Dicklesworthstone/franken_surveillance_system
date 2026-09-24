#![forbid(unsafe_code)]
//! rtpdump import publishes source capsules and preserves malformed or wrongly bound originals.
mod rtpdump_support;
use rtpdump_support::*;
use fss_core::{ContentDigest,SensorId,StreamId,TimestampNs};
use fss_reference::{ReferenceDeployment,ingest::{FileIngestAdapter,FileIngestRequest,FileFormatHint}};
use fss_reference::ingest::rtpdump::import::*;

fn scope()->Result<RtpImportScope,Error>{Ok(RtpImportScope{sensor:SensorId::parse("sensor:rtp-fixture")?,
    stream:StreamId::parse("stream:recorded-rtp")?,receive_time:TimestampNs(1_000_000_000)})}
fn new_directory(label:&str)->Result<std::path::PathBuf,Error>{
    let root=std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));std::fs::create_dir_all(root)?;
    // Never delete or overwrite another test's retained publication evidence.
    for i in 0..1000 {
        let p=root.join(format!("rtpdump-{label}-{}-{i}",std::process::id()));
        match std::fs::create_dir(&p){Ok(())=>return Ok(p),Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>{},Err(e)=>return Err(e.into())}
    }
    Err("test directory allocation exhausted".into())
}
#[test]
fn real_rtp_import_publishes_source_capsules_and_reopens_exactly() -> TestResult {
    let root=new_directory("roundtrip")?;let cx=cx()?;let b=real_dump(true);
    let mut dep=ReferenceDeployment::open(&root,"site:rtpdump-fixture",&cx)?;
    let plan=prepare_rtp_import(&b,scope()?,config(),RtpImportLimits{chunk_bytes:37,..RtpImportLimits::default()},&cx)?;
    assert_eq!(plan.report().nals().len(),nals().len());
    for n in plan.report().nals(){
        assert_eq!(n.capsule.frame_count,0);assert_eq!(n.capsule.source_digest,ContentDigest::sha256(&b[n.source.clone()]));
        assert!(plan.manifest().children().contains(&n.capsule.source_digest));
    }
    let receipt=publish_rtp_import(plan,&cx,&mut dep)?;
    let verified=load_rtp_import(&receipt,&cx,&dep)?;
    assert_eq!(verified.source(),b);assert_eq!(verified.nals().len(),nals().len());
    drop(dep);
    let reopened=ReferenceDeployment::open(&root,"site:rtpdump-fixture",&cx)?;
    let verified=load_rtp_import(&receipt,&cx,&reopened)?;
    assert_eq!(verified.report(),receipt.report());assert_eq!(verified.source(),b);
    for (actual,expected) in verified.nals().iter().zip(nals()){assert_eq!(actual.nal.bytes(),expected);}
    Ok(())
}
#[test]
fn generic_file_adapter_has_an_explicit_owner_bound_rtp_entrypoint() -> TestResult {
    let root=new_directory("file")?;let source=root.join("input.rtp");let b=real_dump(false);
    std::fs::write(&source,&b)?;let cx=cx()?;
    let mut dep=ReferenceDeployment::open(&root.join("deployment"),"site:rtpdump-file",&cx)?;
    let req=FileIngestRequest::new(source,scope()?.sensor,scope()?.stream).with_format_hint(FileFormatHint::RtpPlay);
    let receipt=FileIngestAdapter::ingest_rtp(req,config(),RtpImportLimits::default(),&cx,&mut dep)?;
    assert_eq!(receipt.report().input_digest(),ContentDigest::sha256(&b));
    assert_eq!(load_rtp_import(&receipt,&cx,&dep)?.source(),b);Ok(())
}
#[test]
fn malformed_suffix_is_retained_and_never_relabelled_clean() -> TestResult {
    let mut b=real_dump(false);b.extend_from_slice(&[0,20,0,12]);let cx=cx()?;
    let root=new_directory("tail")?;let mut dep=ReferenceDeployment::open(&root,"site:rtpdump-tail",&cx)?;
    let plan=prepare_rtp_import(&b,scope()?,config(),RtpImportLimits::default(),&cx)?;
    assert!(matches!(plan.report().end(),ImportEnd::FramingRefused(_)));
    let receipt=publish_rtp_import(plan,&cx,&mut dep)?;
    let loaded=load_rtp_import(&receipt,&cx,&dep)?;assert_eq!(loaded.source(),b);
    assert!(matches!(loaded.report().end(),ImportEnd::FramingRefused(_)));Ok(())
}
#[test]
fn wrong_binding_originals_are_preserved_but_never_decode_into_capsules() -> TestResult {
    let b=real_dump(false);let cx=cx()?;let mut cfg=config();cfg.key.ssrc=9;
    let plan=prepare_rtp_import(&b,scope()?,cfg,RtpImportLimits::default(),&cx)?;
    assert!(plan.report().nals().is_empty());
    assert!(plan.report().records().iter().all(|r|matches!(r.disposition,RecordDisposition::StreamRefused(_))));
    assert_eq!(plan.report().input_bytes(),b.len());Ok(())
}
#[test]
fn budgets_refuse_without_an_incomplete_successful_plan() -> TestResult {
    let b=real_dump(false);let cx=cx()?;
    for l in [RtpImportLimits{max_nals:1,..RtpImportLimits::default()},
        RtpImportLimits{max_source_spans:1,..RtpImportLimits::default()},
        RtpImportLimits{max_derived_bytes:1,..RtpImportLimits::default()},
        RtpImportLimits{max_report_bytes:1,..RtpImportLimits::default()},
        RtpImportLimits{max_payload_bytes:b.len()-1,..RtpImportLimits::default()}]{
        assert!(matches!(prepare_rtp_import(&b,scope()?,config(),l,&cx),Err(RtpImportError::Limit)));
    }
    let mut cfg=config();cfg.dump.max_records=1;
    assert!(matches!(prepare_rtp_import(&b,scope()?,cfg,RtpImportLimits::default(),&cx),Err(RtpImportError::Limit)));Ok(())
}
#[test]
fn process_local_ingress_handle_does_not_change_durable_identity() -> TestResult {
    let b=real_dump(true);let cx=cx()?;let a=prepare_rtp_import(&b,scope()?,config(),RtpImportLimits::default(),&cx)?;
    let mut other=config();other.key.ingress=999;
    let b=prepare_rtp_import(&b,scope()?,other,RtpImportLimits::default(),&cx)?;
    assert_eq!(a.manifest(),b.manifest());assert_eq!(a.report_bytes(),b.report_bytes());Ok(())
}
#[test]
fn receive_time_and_stream_epoch_are_bound_into_the_import_identity() -> TestResult {
    let b=real_dump(false);let cx=cx()?;let a=prepare_rtp_import(&b,scope()?,config(),RtpImportLimits::default(),&cx)?;
    let mut s=scope()?;s.receive_time=TimestampNs(2_000_000_000);
    let changed=prepare_rtp_import(&b,s,config(),RtpImportLimits::default(),&cx)?;assert_ne!(a.manifest(),changed.manifest());
    let mut cfg=config();cfg.key.generation=2;
    let changed=prepare_rtp_import(&b,scope()?,cfg,RtpImportLimits::default(),&cx)?;assert_ne!(a.manifest(),changed.manifest());Ok(())
}
#[test]
fn identical_retry_does_not_create_a_different_root_or_capsule_batch() -> TestResult {
    let root=new_directory("retry")?;let cx=cx()?;let b=real_dump(false);
    let mut dep=ReferenceDeployment::open(&root,"site:rtpdump-retry",&cx)?;
    let a=publish_rtp_import(prepare_rtp_import(&b,scope()?,config(),RtpImportLimits::default(),&cx)?,&cx,&mut dep)?;
    let count=dep.ledger().batches().len();
    let b=publish_rtp_import(prepare_rtp_import(&b,scope()?,config(),RtpImportLimits::default(),&cx)?,&cx,&mut dep)?;
    assert_eq!(a.root(),b.root());assert_eq!(dep.ledger().batches().len(),count);Ok(())
}
#[test]
fn cancellation_before_publication_keeps_spool_and_ledger_unchanged() -> TestResult {
    let root=new_directory("cancel")?;let cx=cx()?;let b=real_dump(false);
    let mut dep=ReferenceDeployment::open(&root,"site:rtpdump-cancel",&cx)?;
    let plan=prepare_rtp_import(&b,scope()?,config(),RtpImportLimits::default(),&cx)?;
    let objects=dep.publisher().spool().object_count();let batches=dep.ledger().batches().len();cx.request_cancellation();
    assert!(matches!(publish_rtp_import(plan,&cx,&mut dep),Err(RtpImportError::Cancelled)));
    assert_eq!(dep.publisher().spool().object_count(),objects);assert_eq!(dep.ledger().batches().len(),batches);Ok(())
}
#[test]
fn file_snapshot_read_is_bounded_and_directory_inputs_are_refused() -> TestResult {
    let root=new_directory("bounded_read")?;let path=root.join("input.rtp");let b=real_dump(false);std::fs::write(&path,&b)?;
    let cx=cx()?;
    assert!(matches!(read_rtp_snapshot(std::fs::File::open(&path)?,b.len()-1,&cx),Err(RtpImportError::Limit)));
    assert_eq!(read_rtp_snapshot(std::fs::File::open(&path)?,b.len(),&cx)?,b);
    assert!(read_rtp_snapshot(std::fs::File::open(&root)?,100,&cx).is_err());Ok(())
}
#[test]
fn unavailable_fragment_is_reported_without_a_false_picture() -> TestResult {
    let b=dump(&[(0,false,&[9,0xf0],0),(1,false,&[0x7c,0x85,0xaa],0)]);let cx=cx()?;
    let p=prepare_rtp_import(&b,scope()?,config(),RtpImportLimits::default(),&cx)?;
    assert!(p.report().nals().is_empty());assert!(p.report().final_discard().is_some());Ok(())
}
#[test]
fn capsule_ledger_partitions_are_fixed_and_idempotent_for_larger_captures() -> TestResult {
    let root=new_directory("partitions")?;let cx=cx()?;let mut b=header();
    for sequence in 0..=130_u16 {
        let wire=rtp(sequence,true,&[0x67,0x42,0,0x1e]);record(&mut b,&wire,wire.len() as u16,sequence as u32);
    }
    let mut cfg=config();cfg.dump.max_records=256;
    let mut dep=ReferenceDeployment::open(&root,"site:rtpdump-partitions",&cx)?;
    let receipt=publish_rtp_import(prepare_rtp_import(&b,scope()?,cfg,RtpImportLimits::default(),&cx)?,&cx,&mut dep)?;
    assert_eq!(receipt.report().nals().len(),130);
    let count=dep.ledger().batches().len();
    let again=publish_rtp_import(prepare_rtp_import(&b,scope()?,cfg,RtpImportLimits::default(),&cx)?,&cx,&mut dep)?;
    assert_eq!(receipt.root(),again.root());assert_eq!(count,dep.ledger().batches().len());
    assert_eq!(load_rtp_import(&again,&cx,&dep)?.nals().len(),130);Ok(())
}
#[test]
fn readback_detects_source_corruption_despite_a_retained_publication_receipt() -> TestResult {
    use std::io::Write;
    let root=new_directory("tamper")?;let cx=cx()?;let b=real_dump(false);
    let mut dep=ReferenceDeployment::open(&root,"site:rtpdump-tamper",&cx)?;
    let receipt=publish_rtp_import(prepare_rtp_import(&b,scope()?,config(),RtpImportLimits::default(),&cx)?,&cx,&mut dep)?;
    let path=dep.publisher().spool().object_path(ContentDigest::sha256(&b));
    let mut file=std::fs::OpenOptions::new().append(true).open(path)?;file.write_all(&[1])?;file.sync_all()?;drop(file);
    assert!(load_rtp_import(&receipt,&cx,&dep).is_err());Ok(())
}
#[test]
fn invalid_binding_and_zero_chunk_policy_refuse_before_opening_source() -> TestResult {
    let root=new_directory("preflight")?;let cx=cx()?;
    let mut dep=ReferenceDeployment::open(&root,"site:rtpdump-preflight",&cx)?;
    let owner=scope()?;
    let request=||FileIngestRequest::new(root.join("not-present.rtp"),owner.sensor.clone(),owner.stream.clone());
    let mut cfg=config();cfg.payload_type=255;
    assert!(matches!(FileIngestAdapter::ingest_rtp(request(),cfg,RtpImportLimits::default(),&cx,&mut dep),Err(RtpImportError::Replay(_))));
    let mut req=request();req.limits.chunk_bytes=0;
    assert!(matches!(FileIngestAdapter::ingest_rtp(req,config(),RtpImportLimits::default(),&cx,&mut dep),Err(RtpImportError::Binding)));
    Ok(())
}
