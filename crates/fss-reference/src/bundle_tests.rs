use std::error::Error;
use std::fs;

use fss_core::{CapsuleId, SensorId};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};
use fss_object::{InMemoryObjectStore, ObjectLimits};

use crate::{DeliveryDirective, DeliveryPlan, ReplayBundle, ReplayBundleError, VirtualCameraSpec};

fn bundle() -> Result<ReplayBundle, Box<dyn Error>> {
    let spec = VirtualCameraSpec {
        capture_id: CapsuleId::parse("capture:bundle:1")?,
        sensor_id: SensorId::parse("sensor:side-yard")?,
        seed: 0x1234_5678_9abc_def0,
        packet_count: 5,
        packet_bytes: 48,
        start_ns: 5_000,
        period_ns: 1_000_000,
        uncertainty_ns: 10_000,
    };
    let plan = DeliveryPlan::new(vec![
        DeliveryDirective::exact(1),
        DeliveryDirective::exact(3),
        DeliveryDirective::corrupt(2),
        DeliveryDirective::exact(3),
        DeliveryDirective::exact(5),
    ])?;
    Ok(ReplayBundle::new("site:bundle", spec, plan)?)
}

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "fss-replay-bundle-{}-{name}.journal",
        std::process::id()
    ))
}

#[test]
fn bundle_round_trip_preserves_exact_inputs_and_digest() -> Result<(), Box<dyn Error>> {
    let bundle = bundle()?;
    let bytes = bundle.to_bytes();
    let decoded = ReplayBundle::from_bytes(&bytes)?;
    assert_eq!(decoded, bundle);
    assert_eq!(decoded.digest(), bundle.digest());
    assert_eq!(decoded.to_bytes(), bytes);
    Ok(())
}

#[test]
fn bundle_mutation_is_rejected_before_decode() -> Result<(), Box<dyn Error>> {
    let bundle = bundle()?;
    let mut bytes = bundle.to_bytes();
    let index = bytes.len() / 2;
    bytes[index] ^= 1;
    assert!(matches!(
        ReplayBundle::from_bytes(&bytes),
        Err(ReplayBundleError::BundleDigestMismatch)
    ));
    Ok(())
}

#[test]
fn cursors_are_bundle_bound_and_prefix_verified() -> Result<(), Box<dyn Error>> {
    let bundle = bundle()?;
    let start = bundle.cursor();
    start.validate(&bundle)?;
    assert_eq!(start.next_directive(), 0);
    let middle = start.advance_to(&bundle, 3)?;
    middle.validate(&bundle)?;
    assert_ne!(middle.prefix_digest(), start.prefix_digest());
    let end = middle.advance_to(&bundle, bundle.plan().directives().len())?;
    assert!(end.is_complete(&bundle));

    let mut changed_spec = bundle.spec().clone();
    changed_spec.seed ^= 1;
    let changed = ReplayBundle::new(bundle.site_lineage(), changed_spec, bundle.plan().clone())?;
    assert!(matches!(
        middle.validate(&changed),
        Err(ReplayBundleError::CursorMismatch)
    ));
    assert!(matches!(
        middle.advance_to(&bundle, 2),
        Err(ReplayBundleError::CursorOutOfRange)
    ));
    Ok(())
}

#[test]
fn identical_bundle_replays_produce_identical_semantic_outputs() -> Result<(), Box<dyn Error>> {
    let bundle = bundle()?;
    let first_path = temp_journal("first");
    let second_path = temp_journal("second");
    let _ = fs::remove_file(&first_path);
    let _ = fs::remove_file(&second_path);

    let mut first_objects = InMemoryObjectStore::new(ObjectLimits::new(256, 2 * 1024 * 1024));
    let mut first_ledger = DurableReferenceLedger::open(
        &first_path,
        bundle.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let first = bundle.replay(&mut first_objects, &mut first_ledger)?;

    let decoded = ReplayBundle::from_bytes(&bundle.to_bytes())?;
    let mut second_objects = InMemoryObjectStore::new(ObjectLimits::new(256, 2 * 1024 * 1024));
    let mut second_ledger = DurableReferenceLedger::open(
        &second_path,
        decoded.site_lineage(),
        IncompleteTailPolicy::Reject,
    )?;
    let second = decoded.replay(&mut second_objects, &mut second_ledger)?;

    assert_eq!(first, second);
    assert_eq!(first_ledger.batches(), second_ledger.batches());
    assert_eq!(
        first_ledger.current().anchor,
        second_ledger.current().anchor
    );

    let _ = fs::remove_file(first_path);
    let _ = fs::remove_file(second_path);
    Ok(())
}

#[test]
fn replay_refuses_to_append_into_non_genesis_authority() -> Result<(), Box<dyn Error>> {
    let bundle = bundle()?;
    let path = temp_journal("non-genesis");
    let _ = fs::remove_file(&path);
    let mut objects = InMemoryObjectStore::new(ObjectLimits::new(256, 2 * 1024 * 1024));
    let mut ledger =
        DurableReferenceLedger::open(&path, bundle.site_lineage(), IncompleteTailPolicy::Reject)?;
    let _ = bundle.replay(&mut objects, &mut ledger)?;
    assert!(matches!(
        bundle.replay(&mut objects, &mut ledger),
        Err(ReplayBundleError::NonGenesisAuthority)
    ));
    assert_eq!(ledger.batches().len(), 1);
    let _ = fs::remove_file(path);
    Ok(())
}
