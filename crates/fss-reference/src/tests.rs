use std::error::Error;
use std::fs;

use fss_core::{CapsuleId, SensorId};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{
    DeliveryDirective, DeliveryPlan, ReferenceError, VirtualCameraSpec, generate_source,
    run_reference_capture,
};

fn spec() -> Result<VirtualCameraSpec, Box<dyn Error>> {
    Ok(VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:reference:1")?,
        sensor_id: SensorId::parse("sensor:rear-yard")?,
        seed: 0x5eed_cafe_f00d_u64,
        packet_count: 4,
        packet_bytes: 32,
        start_ns: 1_000_000,
        period_ns: 33_000_000,
        uncertainty_ns: 500_000,
    })
}

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-reference-{}-{name}.journal",
        std::process::id()
    ))
}

#[test]
fn identity_capture_links_source_delivery_custody_and_authority() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("identity");
    let _ = fs::remove_file(&path);
    let spec = spec()?;
    let plan = DeliveryPlan::identity(spec.packet_count)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:reference", IncompleteTailPolicy::Reject)?;

    let capture = run_reference_capture(&spec, &plan, &mut objects, &mut ledger)?;
    assert!(capture.continuity.exact_once_ordered);
    assert!(capture.continuity.missing_sequences.is_empty());
    assert_eq!(capture.receipt.source_packet_count, 4);
    assert_eq!(capture.receipt.delivered_packet_count, 4);
    assert_eq!(capture.receipt.authority_anchor.commit_sequence, 1);
    assert_eq!(
        objects.verify_closure(capture.receipt.capture_root)?,
        capture.receipt.closure_object_count
    );

    let batch = &ledger.batches()[0];
    assert_eq!(batch.children, vec![capture.receipt.capture_root]);
    assert_eq!(
        batch.deltas[0].payload_digest,
        capture.receipt.capture_root
    );
    assert_eq!(
        batch.deltas[0].witness_digest,
        Some(capture.receipt.continuity_digest)
    );

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn transport_faults_never_mutate_source_truth() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("faults");
    let _ = fs::remove_file(&path);
    let spec = spec()?;
    let plan = DeliveryPlan::new(vec![
        DeliveryDirective::exact(2),
        DeliveryDirective::corrupt(1),
        DeliveryDirective::exact(2),
        DeliveryDirective::exact(4),
    ])?;
    let expected_source = generate_source(&spec)?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:reference", IncompleteTailPolicy::Reject)?;

    let capture = run_reference_capture(&spec, &plan, &mut objects, &mut ledger)?;
    assert_eq!(capture.source_packets, expected_source);
    assert_eq!(capture.continuity.missing_sequences, vec![3]);
    assert_eq!(capture.continuity.duplicate_sequences, vec![2]);
    assert_eq!(capture.continuity.corrupted_sequences, vec![1]);
    assert!(capture.continuity.reordered);
    assert!(!capture.continuity.exact_once_ordered);

    let corrupted = capture
        .delivery_packets
        .iter()
        .find(|packet| packet.source_sequence == 1)
        .ok_or(ReferenceError::InvalidSpec("missing_corrupt_delivery"))?;
    let source = capture
        .source_packets
        .iter()
        .find(|packet| packet.sequence == 1)
        .ok_or(ReferenceError::InvalidSpec("missing_source_packet"))?;
    assert_eq!(source.digest, expected_source[0].digest);
    assert_ne!(corrupted.observed_digest, source.digest);
    assert_eq!(objects.read_verified(source.digest)?, source.bytes);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn repeated_runs_are_semantically_identical() -> Result<(), Box<dyn Error>> {
    let first_path = temp_journal("deterministic-a");
    let second_path = temp_journal("deterministic-b");
    let _ = fs::remove_file(&first_path);
    let _ = fs::remove_file(&second_path);
    let spec = spec()?;
    let plan = DeliveryPlan::new(vec![
        DeliveryDirective::exact(1),
        DeliveryDirective::exact(3),
        DeliveryDirective::corrupt(2),
        DeliveryDirective::exact(4),
    ])?;

    let mut first_objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut first_ledger = DurableReferenceLedger::open(
        &first_path,
        "site:reference",
        IncompleteTailPolicy::Reject,
    )?;
    let first =
        run_reference_capture(&spec, &plan, &mut first_objects, &mut first_ledger)?;

    let mut second_objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut second_ledger = DurableReferenceLedger::open(
        &second_path,
        "site:reference",
        IncompleteTailPolicy::Reject,
    )?;
    let second =
        run_reference_capture(&spec, &plan, &mut second_objects, &mut second_ledger)?;

    assert_eq!(first, second);
    assert_eq!(first_ledger.current().anchor, second_ledger.current().anchor);
    assert_eq!(first_ledger.batches(), second_ledger.batches());

    let _ = fs::remove_file(first_path);
    let _ = fs::remove_file(second_path);
    Ok(())
}

#[test]
fn invalid_delivery_plan_fails_before_object_or_authority_mutation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("invalid-plan");
    let _ = fs::remove_file(&path);
    let spec = spec()?;
    let plan = DeliveryPlan::new(vec![DeliveryDirective::exact(5)])?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:reference", IncompleteTailPolicy::Reject)?;

    assert!(matches!(
        run_reference_capture(&spec, &plan, &mut objects, &mut ledger),
        Err(ReferenceError::UnknownSourceSequence(5))
    ));
    assert_eq!(objects.object_count(), 0);
    assert_eq!(ledger.current().anchor.commit_sequence, 0);
    assert!(ledger.batches().is_empty());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn fully_lost_delivery_is_not_mistaken_for_quiet_source() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("all-lost");
    let _ = fs::remove_file(&path);
    let spec = spec()?;
    let plan = DeliveryPlan::new(Vec::new())?;
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(128, 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, "site:reference", IncompleteTailPolicy::Reject)?;

    let capture = run_reference_capture(&spec, &plan, &mut objects, &mut ledger)?;
    assert_eq!(capture.source_packets.len(), 4);
    assert!(capture.delivery_packets.is_empty());
    assert_eq!(capture.continuity.missing_sequences, vec![1, 2, 3, 4]);
    assert!(!capture.continuity.exact_once_ordered);
    assert_eq!(ledger.current().anchor.commit_sequence, 1);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn source_generation_is_sensor_bound() -> Result<(), Box<dyn Error>> {
    let first = spec()?;
    let mut second = first.clone();
    second.sensor_id = SensorId::parse("sensor:front-door")?;
    let first_packets = generate_source(&first)?;
    let second_packets = generate_source(&second)?;
    assert_ne!(first_packets[0].digest, second_packets[0].digest);
    Ok(())
}
