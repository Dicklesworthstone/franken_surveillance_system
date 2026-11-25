#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-147` (`fss-x4a.14.18`): model package RaptorQ/GF(256)
//! protection, post-repair digest recovery, license- & closure-gated root-last ATP activation,
//! and atomic generation rollback.

use fss_core::{CalibrationGeneration, ContentDigest, ModelGeneration, SchemaId, TimestampNs};
use fss_object::independent_reconstruct::RepairFallbackBundle;
use fss_object::model_atp_activation::{
    ATP_MODEL_ACTIVATION_RECEIPT_DOMAIN, MODEL_ATP_RECEIPT_MAGIC, MODEL_ATP_RECEIPT_VERSION,
    ModelActivationAuthority, ModelAtpActivationReceipt, ModelAtpActivator, ModelAtpError,
    ModelExecutionGenerationPin, ModelPackageAtpState, ProtectedModelPackage,
};
use fss_object::model_license_policy::{ModelLicensePolicy, ModelUseProfile};
use fss_object::model_manifest::{ModelId, ModelLicenseRecord, ModelManifestV1};
use fss_object::repair_gate::{RepairAuthorityContext, RepairLease};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn d(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn build_manifest(
    gen_str: &str,
    spdx: &str,
    weights: &[u8],
    license_text: &[u8],
    use_approved: bool,
) -> Result<ModelManifestV1, Box<dyn std::error::Error>> {
    let license = ModelLicenseRecord::new(
        spdx,
        Some(ContentDigest::sha256(license_text)),
        use_approved,
        vec![],
        "https://models.example.invalid/rfdetr-pure-rust",
        vec![ContentDigest::sha256(weights)],
        Some("rev-2026-08-31".to_owned()),
    )?;
    Ok(ModelManifestV1::new(
        ModelId::parse("MOD-RFDETR-001")?,
        ModelGeneration::parse(gen_str)?,
        ContentDigest::sha256(weights),
        SchemaId::parse("fss.tensor.rgb_u8_640x640.v1")?,
        SchemaId::parse("fss.detections.boxes.v1")?,
        CalibrationGeneration::parse("cal:cam-front:v1")?,
        license,
    )?)
}

fn pin_for(gen_str: &str) -> ModelExecutionGenerationPin {
    ModelExecutionGenerationPin {
        model_generation: gen_str.to_owned(),
        preprocess_generation: "prep:letterbox:v1".to_owned(),
        numeric_generation: "num:f32-exact:v1".to_owned(),
        kernel_generation: "kern:scalar-ref:v1".to_owned(),
        memory_plan_generation: "mem:static-arena:v1".to_owned(),
        calibration_generation: "cal:cam-front:v1".to_owned(),
    }
}

#[test]
fn model_package_gf256_protection_erasure_recovery_root_last_activation_and_rollback() -> TestResult
{
    let cb = d("contract-basis-147");
    let weights_v1: Vec<u8> = (0..1024_usize)
        .map(|i| ((i * 37 + 11) % 251) as u8)
        .collect();
    let license_v1 = b"Apache License, Version 2.0 (model v1)".to_vec();
    let manifest_v1 = build_manifest(
        "model:rfdetr:v1",
        "Apache-2.0",
        &weights_v1,
        &license_v1,
        true,
    )?;

    // 1. Protect v1 with GF(256) repair symbols (symbol_size=256, k=4, r=3).
    let mut pkg_v1 = ProtectedModelPackage::protect_package(
        manifest_v1,
        pin_for("model:rfdetr:v1"),
        weights_v1.clone(),
        Some(license_v1),
        256,
        3,
        1,
        cb,
        5,
        false,
    )?;
    assert_eq!(pkg_v1.state, ModelPackageAtpState::Protected);

    // 2. Erase raw weights blob completely from cold_blobs and drop 2 source symbols, proving
    //    FSS-135 independent reconstruction + FSS-128 GF(256) repair recovers weights bit-identically!
    let weights_digest = ContentDigest::sha256(&weights_v1);
    pkg_v1.cold_blobs.blobs.remove(&weights_digest);
    let art = pkg_v1
        .protected_artifacts
        .get(&weights_digest)
        .ok_or("missing weights repair artifact")?
        .clone();
    // Drop ESIs 0 and 2 (2 erasures <= r=3) and pass remaining symbols through RepairFallbackBundle!
    let degraded_symbols: Vec<_> = art
        .symbols
        .iter()
        .filter(|s| s.esi != 0 && s.esi != 2)
        .cloned()
        .collect();
    let lease = RepairLease {
        lease_id: "lease-147-weights".to_owned(),
        plan_digest: art.repair_plan.plan_digest,
        fence: 10,
        expires_at: TimestampNs(1_700_000_999_000),
        authority_generation: 5,
        active: true,
    };
    let repair_auth = RepairAuthorityContext::active(cb, 5, 2);

    // Retrievability drill with erased weights + GF(256) fallback bundle succeeds -> Retrievable!
    let _drill_proof = pkg_v1.verify_retrievability_drill(
        &repair_auth,
        vec![(
            weights_digest,
            RepairFallbackBundle {
                plan: art.repair_plan.clone(),
                lease: lease.clone(),
                min_fence: 10,
                symbols: degraded_symbols.clone(),
            },
        )],
        TimestampNs(1_700_000_147_100),
        false,
    )?;
    assert_eq!(pkg_v1.state, ModelPackageAtpState::Retrievable);

    // Also restore recovered weights back into cold_blobs via recover_artifact_via_repair!
    let recovered = pkg_v1.recover_artifact_via_repair(
        weights_digest,
        &repair_auth,
        &lease,
        10,
        &degraded_symbols,
        TimestampNs(1_700_000_147_150),
        false,
    )?;
    assert_eq!(recovered, weights_v1);

    // 3. Activate v1 root-last with surveillance license policy & explicit owner approval!
    let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::SurveillanceMonitoring);
    let auth = ModelActivationAuthority {
        contract_basis_digest: cb,
        authority_generation: 5,
        expected_authority_generation: 5,
        privacy_epoch: 2,
        activation_capability_active: true,
        privacy_active: true,
        owner_approval_digest: Some(d("owner-approval-v1")),
    };
    let mut activator = ModelAtpActivator::new();
    let act_v1 = activator.activate_generation(
        &mut pkg_v1,
        &policy,
        &auth,
        TimestampNs(1_700_000_147_200),
        false,
    )?;
    assert_eq!(act_v1.state, ModelPackageAtpState::Active);
    assert_eq!(act_v1.prior_active_generation, None);
    assert_eq!(
        ATP_MODEL_ACTIVATION_RECEIPT_DOMAIN,
        "fss.atp_model_activation_receipt.v1"
    );

    // 4. Activate v2 superseding v1, then atomically roll back to v1!
    let weights_v2: Vec<u8> = (0..1024_usize)
        .map(|i| ((i * 53 + 7) % 251) as u8)
        .collect();
    let license_v2 = b"MIT License (model v2)".to_vec();
    let manifest_v2 = build_manifest("model:rfdetr:v2", "MIT", &weights_v2, &license_v2, true)?;
    let mut pkg_v2 = ProtectedModelPackage::protect_package(
        manifest_v2,
        pin_for("model:rfdetr:v2"),
        weights_v2,
        Some(license_v2),
        256,
        2,
        2,
        cb,
        5,
        false,
    )?;
    let act_v2 = activator.activate_generation(
        &mut pkg_v2,
        &policy,
        &auth,
        TimestampNs(1_700_000_147_300),
        false,
    )?;
    assert_eq!(
        act_v2.prior_active_generation.as_deref(),
        Some("model:rfdetr:v1")
    );
    assert_eq!(
        activator
            .active_receipt("MOD-RFDETR-001")
            .map(|r| r.generation_pin.model_generation.as_str()),
        Some("model:rfdetr:v2")
    );

    // Re-activating the already-active generation MUST fail closed and MUST NOT clobber v1 rollback!
    assert!(matches!(
        activator.activate_generation(
            &mut pkg_v2,
            &policy,
            &auth,
            TimestampNs(1_700_000_147_350),
            false,
        ),
        Err(ModelAtpError::InvalidInput(_))
    ));
    // Cross-contract-basis rollback MUST fail closed AND preserve v1 rollback target atomically!
    let mut wrong_cb_auth = auth.clone();
    wrong_cb_auth.contract_basis_digest = d("wrong-basis-147");
    assert!(matches!(
        activator.rollback_to_prior(
            "MOD-RFDETR-001",
            &wrong_cb_auth,
            TimestampNs(1_700_000_147_375),
            false,
        ),
        Err(ModelAtpError::AuthorityRefused(_))
    ));

    let rb = activator.rollback_to_prior(
        "MOD-RFDETR-001",
        &auth,
        TimestampNs(1_700_000_147_400),
        false,
    )?;
    assert_eq!(rb.state, ModelPackageAtpState::RolledBack);
    assert_eq!(rb.generation_pin.model_generation, "model:rfdetr:v1");
    assert_eq!(
        rb.prior_active_generation.as_deref(),
        Some("model:rfdetr:v2")
    );
    assert_eq!(
        activator
            .active_receipt("MOD-RFDETR-001")
            .map(|r| r.generation_pin.model_generation.as_str()),
        Some("model:rfdetr:v1")
    );

    // Binary wire codec round-trip (`FSSMATP1` v1).
    let wire = rb.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &MODEL_ATP_RECEIPT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        MODEL_ATP_RECEIPT_VERSION
    );
    assert_eq!(ModelAtpActivationReceipt::from_canonical_bytes(&wire)?, rb);

    emit_caplog(
        "fss147_gf256_recovery_activation_and_rollback",
        "model_gf256_repair_root_last_activation_rollback_and_wire_verified",
        "model_gf256_repair_root_last_activation_rollback_and_wire_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn model_atp_refuses_latest_license_violation_missing_approval_corrupt_blob_and_wire() -> TestResult
{
    let cb = d("contract-basis-147-faults");
    // 1. `latest` generation alias MUST be refused immediately!
    assert!(matches!(
        ModelAtpActivator::parse_pinned_generation("model:rfdetr:latest"),
        Err(ModelAtpError::InvalidInput(_))
    ));

    // 2. Surveillance-incompatible license (`OpenRAIL-M`) MUST fail closed at activation!
    let weights = b"model-weights-openrail-256-bytes-padded-payload".to_vec();
    let lic_txt = b"OpenRAIL-M License".to_vec();
    let bad_lic_manifest =
        build_manifest("model:rfdetr:v9", "OpenRAIL-M", &weights, &lic_txt, true)?;
    let mut bad_pkg = ProtectedModelPackage::protect_package(
        bad_lic_manifest,
        pin_for("model:rfdetr:v9"),
        weights.clone(),
        Some(lic_txt.clone()),
        32,
        2,
        1,
        cb,
        1,
        false,
    )?;
    let surv_policy =
        ModelLicensePolicy::default_for_profile(ModelUseProfile::SurveillanceMonitoring);
    let auth = ModelActivationAuthority {
        contract_basis_digest: cb,
        authority_generation: 1,
        expected_authority_generation: 1,
        privacy_epoch: 1,
        activation_capability_active: true,
        privacy_active: true,
        owner_approval_digest: Some(d("approval")),
    };
    let mut activator = ModelAtpActivator::new();
    assert!(matches!(
        activator.activate_generation(
            &mut bad_pkg,
            &surv_policy,
            &auth,
            TimestampNs(1_700_000_147_500),
            false,
        ),
        Err(ModelAtpError::LicenseRejected(_))
    ));
    assert!(activator.active_receipt("MOD-RFDETR-001").is_none());

    // 3. Missing owner_approval_digest refuses silent activation (ATP delivery != activation)!
    let good_manifest = build_manifest("model:rfdetr:v10", "MIT", &weights, &lic_txt, true)?;
    let mut good_pkg = ProtectedModelPackage::protect_package(
        good_manifest,
        pin_for("model:rfdetr:v10"),
        weights.clone(),
        Some(lic_txt),
        32,
        2,
        1,
        cb,
        1,
        false,
    )?;
    let mut no_approval = auth.clone();
    no_approval.owner_approval_digest = None;
    assert!(matches!(
        activator.activate_generation(
            &mut good_pkg,
            &surv_policy,
            &no_approval,
            TimestampNs(1_700_000_147_510),
            false,
        ),
        Err(ModelAtpError::AuthorityRefused(_))
    ));

    // 4. Cooperative cancellation fails closed without activating.
    assert_eq!(
        activator.activate_generation(
            &mut good_pkg,
            &surv_policy,
            &auth,
            TimestampNs(1_700_000_147_520),
            true,
        ),
        Err(ModelAtpError::Cancelled)
    );

    // 5. Missing child blob (incomplete root-last closure!) quarantines and refuses activation!
    let w_digest = ContentDigest::sha256(&weights);
    let saved = good_pkg
        .cold_blobs
        .blobs
        .remove(&w_digest)
        .ok_or("expected weights blob")?;
    assert!(matches!(
        activator.activate_generation(
            &mut good_pkg,
            &surv_policy,
            &auth,
            TimestampNs(1_700_000_147_530),
            false,
        ),
        Err(ModelAtpError::IntegrityOrRepairFailed(_))
    ));
    assert_eq!(good_pkg.state, ModelPackageAtpState::Quarantined);

    // Restore weights, activate cleanly, and verify hostile wire decoding on `FSSMATP1`!
    good_pkg.cold_blobs.insert_verified_blob(saved);
    let receipt = activator.activate_generation(
        &mut good_pkg,
        &surv_policy,
        &auth,
        TimestampNs(1_700_000_147_540),
        false,
    )?;
    let wire = receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ModelAtpActivationReceipt::from_canonical_bytes(&bad_magic),
        Err(ModelAtpError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&88_u32.to_be_bytes());
    assert_eq!(
        ModelAtpActivationReceipt::from_canonical_bytes(&bad_ver),
        Err(ModelAtpError::UnsupportedVersion { version: 88 })
    );
    assert!(matches!(
        ModelAtpActivationReceipt::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(ModelAtpError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        ModelAtpActivationReceipt::from_canonical_bytes(&bit_flip),
        Err(ModelAtpError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x42);
    assert!(matches!(
        ModelAtpActivationReceipt::from_canonical_bytes(&trailing),
        Err(ModelAtpError::MalformedWire(_))
    ));

    emit_caplog(
        "fss147_faults_latest_license_approval_closure_wire",
        "latest_license_approval_incomplete_closure_cancel_and_wire_failed_closed",
        "latest_license_approval_incomplete_closure_cancel_and_wire_failed_closed",
        "pass",
    );
    Ok(())
}
