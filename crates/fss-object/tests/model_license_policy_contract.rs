#![forbid(unsafe_code)]
//! Contract tests for model license/profile policy checker (FSS-075 / fss-x4a.14.6).

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{CalibrationGeneration, ContentDigest, ModelGeneration, SchemaId, TimestampNs};
use fss_object::{
    ImportOutcome, MAX_POLICY_ALLOWED_LICENSES_COUNT,
    MAX_POLICY_FORBIDDEN_RESTRICTIONS_COUNT, MAX_POLICY_KNOWN_TERMS_COUNT, MAX_POLICY_NAME_LEN,
    MAX_PROFILE_NAME_LEN, ModelId, ModelLicenseDecision, ModelLicensePolicy,
    ModelLicensePolicyError, ModelLicenseRecord, ModelManifestV1, ModelPackage,
    ModelPackageArtifact, ModelPackageError, ModelPackageImporter, ModelPackageLimits,
    ModelUseProfile, SpoolLimits, StagingSpool,
};

type TestResult = Result<(), Box<dyn Error>>;

const GENERATION: &str = "model:rfdetr:fp16:v1";

fn temp_dir(test_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = option_env!("CARGO_TARGET_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let dir = base
        .join("fss_license_policy_test")
        .join(format!("{}-{test_name}", std::process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn sample_license_record(
    spdx: &str,
    use_approved: bool,
    restrictions: Vec<String>,
    text_digest: Option<ContentDigest>,
) -> ModelLicenseRecord {
    ModelLicenseRecord {
        spdx_or_identity: spdx.to_string(),
        text_digest,
        use_approved,
        restrictions,
        source_identity: "https://example.com/weights".to_string(),
        artifact_digests: vec![ContentDigest::sha256(b"provenance-part-1")],
        upstream_revision: Some("rev-1".to_string()),
    }
}

fn sample_manifest_with_license(
    license: ModelLicenseRecord,
) -> Result<ModelManifestV1, Box<dyn Error>> {
    let weights_digest = ContentDigest::sha256(b"weights");
    Ok(ModelManifestV1::new(
        ModelId::parse("MOD-RFDETR-001")?,
        ModelGeneration::parse(GENERATION)?,
        weights_digest,
        SchemaId::parse("fss.model_input.v1")?,
        SchemaId::parse("fss.model_output.v1")?,
        CalibrationGeneration::parse("cal:camera-rig:v1")?,
        license,
    )?)
}

fn sample_package_with_license(license: ModelLicenseRecord) -> Result<ModelPackage, Box<dyn Error>> {
    let weights_payload = b"weights-bytes-v1".to_vec();
    let weights_digest = ContentDigest::sha256(&weights_payload);

    let license_payload = b"Apache-2.0 legal text".to_vec();
    let license_digest = ContentDigest::sha256(&license_payload);

    let prov_payload = b"provenance-part-1".to_vec();
    let prov_digest = ContentDigest::sha256(&prov_payload);

    let mut lic = license;
    lic.text_digest = Some(license_digest);
    lic.artifact_digests = vec![prov_digest];

    let manifest = ModelManifestV1::new(
        ModelId::parse("MOD-RFDETR-001")?,
        ModelGeneration::parse(GENERATION)?,
        weights_digest,
        SchemaId::parse("fss.model_input.v1")?,
        SchemaId::parse("fss.model_output.v1")?,
        CalibrationGeneration::parse("cal:camera-rig:v1")?,
        lic,
    )?;

    let artifacts = vec![
        ModelPackageArtifact {
            name: "weights.bin".to_string(),
            digest: weights_digest,
            payload: weights_payload,
        },
        ModelPackageArtifact {
            name: "LICENSE.txt".to_string(),
            digest: license_digest,
            payload: license_payload,
        },
        ModelPackageArtifact {
            name: "provenance.bin".to_string(),
            digest: prov_digest,
            payload: prov_payload,
        },
    ];

    Ok(ModelPackage::new(manifest, artifacts)?)
}

fn sample_spool(dir: &Path) -> Result<StagingSpool, Box<dyn Error>> {
    let limits = SpoolLimits::new(64, 100 * 1024 * 1024, 10 * 1024 * 1024, 64);
    Ok(StagingSpool::open(dir, limits)?)
}

#[test]
fn test_missing_license_fails_closed() -> TestResult {
    let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);

    // Empty SPDX
    let lic_empty = sample_license_record("", true, vec![], Some(ContentDigest::sha256(b"text")));
    let res = policy.check_license(&lic_empty);
    assert!(matches!(res, Err(ModelLicensePolicyError::MissingLicense)));

    // Whitespace SPDX
    let lic_ws = sample_license_record("   ", true, vec![], Some(ContentDigest::sha256(b"text")));
    let res = policy.check_license(&lic_ws);
    assert!(matches!(res, Err(ModelLicensePolicyError::MissingLicense)));

    Ok(())
}

#[test]
fn test_missing_profile_fails_closed() -> TestResult {
    // Empty profile string
    let res = ModelUseProfile::parse("");
    assert!(matches!(res, Err(ModelLicensePolicyError::MissingProfile)));

    let res_ws = ModelUseProfile::parse("   ");
    assert!(matches!(res_ws, Err(ModelLicensePolicyError::MissingProfile)));

    Ok(())
}

#[test]
fn test_missing_license_text_digest_when_required_fails_closed() -> TestResult {
    let mut policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);
    policy.set_require_text_digest(true);

    let lic_no_text = sample_license_record("Apache-2.0", true, vec![], None);
    let res = policy.check_license(&lic_no_text);
    assert!(matches!(
        res,
        Err(ModelLicensePolicyError::MissingLicenseTextDigest)
    ));

    // With text digest it succeeds
    let lic_with_text = sample_license_record(
        "Apache-2.0",
        true,
        vec![],
        Some(ContentDigest::sha256(b"text")),
    );
    assert!(policy.check_license(&lic_with_text).is_ok());

    Ok(())
}

#[test]
fn test_unknown_license_fails_closed() -> TestResult {
    let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);

    let unapproved_spdx = "GPL-3.0-only";
    let lic = sample_license_record(
        unapproved_spdx,
        true,
        vec![],
        Some(ContentDigest::sha256(b"text")),
    );
    let res = policy.check_license(&lic);
    match res {
        Err(ModelLicensePolicyError::UnknownLicense { spdx_or_identity }) => {
            assert_eq!(spdx_or_identity, unapproved_spdx);
        }
        other => return Err(format!("expected UnknownLicense, got {other:?}").into()),
    }

    let proprietary_unknown = "Proprietary-Custom-Unknown-123";
    let lic2 = sample_license_record(
        proprietary_unknown,
        true,
        vec![],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic2) {
        Err(ModelLicensePolicyError::UnknownLicense { spdx_or_identity }) => {
            assert_eq!(spdx_or_identity, proprietary_unknown);
        }
        other => return Err(format!("expected UnknownLicense, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_unknown_license_term_fails_closed() -> TestResult {
    // AGENTS.md / acceptance: unknown licence terms are never treated as permissive
    let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);

    let unknown_term = "unrecognized_custom_clause_99";
    let lic = sample_license_record(
        "Apache-2.0",
        true,
        vec![unknown_term.to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic) {
        Err(ModelLicensePolicyError::UnknownLicenseTerm { term }) => {
            assert_eq!(term, unknown_term);
        }
        other => return Err(format!("expected UnknownLicenseTerm, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_expired_license_fails_closed() -> TestResult {
    let mut policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);
    let eval_time = TimestampNs(2_000_000_000);
    policy.set_evaluation_time(Some(eval_time));

    // Expiry in the past (1_000_000_000 < 2_000_000_000)
    let lic_expired = sample_license_record(
        "Apache-2.0",
        true,
        vec!["valid_until:1000000000".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic_expired) {
        Err(ModelLicensePolicyError::LicenseExpired {
            expiry,
            evaluated_at,
        }) => {
            assert_eq!(expiry, TimestampNs(1_000_000_000));
            assert_eq!(evaluated_at, eval_time);
        }
        other => return Err(format!("expected LicenseExpired, got {other:?}").into()),
    }

    // expires_at variant in the past
    let lic_expired2 = sample_license_record(
        "Apache-2.0",
        true,
        vec!["expires_at:1500000000".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic_expired2) {
        Err(ModelLicensePolicyError::LicenseExpired {
            expiry,
            evaluated_at,
        }) => {
            assert_eq!(expiry, TimestampNs(1_500_000_000));
            assert_eq!(evaluated_at, eval_time);
        }
        other => return Err(format!("expected LicenseExpired, got {other:?}").into()),
    }

    // Future expiry passes (3_000_000_000 > 2_000_000_000)
    let lic_valid = sample_license_record(
        "Apache-2.0",
        true,
        vec!["valid_until:3000000000".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    assert!(policy.check_license(&lic_valid).is_ok());

    Ok(())
}

#[test]
fn test_invalid_expiry_format_fails_closed() -> TestResult {
    let mut policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);
    policy.set_evaluation_time(Some(TimestampNs(1_000)));

    let lic_invalid = sample_license_record(
        "Apache-2.0",
        true,
        vec!["valid_until:not_a_number".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic_invalid) {
        Err(ModelLicensePolicyError::InvalidExpiryFormat { raw }) => {
            assert_eq!(raw, "valid_until:not_a_number");
        }
        other => return Err(format!("expected InvalidExpiryFormat, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_use_not_approved_fails_closed() -> TestResult {
    let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);

    let lic = sample_license_record(
        "Apache-2.0",
        false, // Not approved!
        vec!["internal_evaluation_only".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    assert!(matches!(
        policy.check_license(&lic),
        Err(ModelLicensePolicyError::UseNotApproved)
    ));

    Ok(())
}

#[test]
fn test_commercial_profile_refuses_non_commercial_terms() -> TestResult {
    let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::CommercialProduction);

    // internal_evaluation_only is refused for commercial production
    let lic1 = sample_license_record(
        "Apache-2.0",
        true,
        vec!["internal_evaluation_only".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic1) {
        Err(ModelLicensePolicyError::NotPermittedForUse {
            requested_profile,
            conflicting_restriction,
        }) => {
            assert_eq!(requested_profile, ModelUseProfile::CommercialProduction);
            assert_eq!(conflicting_restriction, "internal_evaluation_only");
        }
        other => return Err(format!("expected NotPermittedForUse, got {other:?}").into()),
    }

    // research_only is refused for commercial production
    let lic2 = sample_license_record(
        "Apache-2.0",
        true,
        vec!["research_only".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic2) {
        Err(ModelLicensePolicyError::NotPermittedForUse {
            requested_profile,
            conflicting_restriction,
        }) => {
            assert_eq!(requested_profile, ModelUseProfile::CommercialProduction);
            assert_eq!(conflicting_restriction, "research_only");
        }
        other => return Err(format!("expected NotPermittedForUse, got {other:?}").into()),
    }

    // no_commercial_use is refused for commercial production
    let lic3 = sample_license_record(
        "Apache-2.0",
        true,
        vec!["no_commercial_use".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic3) {
        Err(ModelLicensePolicyError::NotPermittedForUse {
            requested_profile,
            conflicting_restriction,
        }) => {
            assert_eq!(requested_profile, ModelUseProfile::CommercialProduction);
            assert_eq!(conflicting_restriction, "no_commercial_use");
        }
        other => return Err(format!("expected NotPermittedForUse, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_surveillance_profile_refuses_surveillance_restrictions() -> TestResult {
    let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::SurveillanceMonitoring);

    let lic_no_surveillance = sample_license_record(
        "Apache-2.0",
        true,
        vec!["no_surveillance".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic_no_surveillance) {
        Err(ModelLicensePolicyError::NotPermittedForUse {
            requested_profile,
            conflicting_restriction,
        }) => {
            assert_eq!(requested_profile, ModelUseProfile::SurveillanceMonitoring);
            assert_eq!(conflicting_restriction, "no_surveillance");
        }
        other => return Err(format!("expected NotPermittedForUse, got {other:?}").into()),
    }

    let lic_no_face = sample_license_record(
        "Apache-2.0",
        true,
        vec!["no_facial_recognition".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic_no_face) {
        Err(ModelLicensePolicyError::NotPermittedForUse {
            requested_profile,
            conflicting_restriction,
        }) => {
            assert_eq!(requested_profile, ModelUseProfile::SurveillanceMonitoring);
            assert_eq!(conflicting_restriction, "no_facial_recognition");
        }
        other => return Err(format!("expected NotPermittedForUse, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_noncommercial_spdx_incompatible_with_commercial_profile() -> TestResult {
    let mut policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::CommercialProduction);
    // Allow CC-BY-NC-4.0 in policy general registry
    policy.allow_license("CC-BY-NC-4.0")?;

    let lic = sample_license_record(
        "CC-BY-NC-4.0",
        true,
        vec![],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic) {
        Err(ModelLicensePolicyError::LicenseIncompatibleWithProfile {
            spdx_or_identity,
            requested_profile,
        }) => {
            assert_eq!(spdx_or_identity, "CC-BY-NC-4.0");
            assert_eq!(requested_profile, ModelUseProfile::CommercialProduction);
        }
        other => return Err(format!("expected LicenseIncompatibleWithProfile, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_forbidden_restriction_fails_closed() -> TestResult {
    let mut policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);
    policy.forbid_restriction("no_unredacted_retention")?;

    let lic = sample_license_record(
        "Apache-2.0",
        true,
        vec!["no_unredacted_retention".to_string()],
        Some(ContentDigest::sha256(b"text")),
    );
    match policy.check_license(&lic) {
        Err(ModelLicensePolicyError::ForbiddenRestriction { restriction }) => {
            assert_eq!(restriction, "no_unredacted_retention");
        }
        other => return Err(format!("expected ForbiddenRestriction, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_profile_name_exact_and_over_bound() -> TestResult {
    // 64 bytes is exact bound -> succeeds
    let at_bound = "p".repeat(MAX_PROFILE_NAME_LEN);
    let profile = ModelUseProfile::parse(&at_bound)?;
    assert_eq!(profile.as_str(), at_bound);

    // 65 bytes is bound + 1 -> fails
    let over_bound = "p".repeat(MAX_PROFILE_NAME_LEN + 1);
    let res = ModelUseProfile::parse(&over_bound);
    match res {
        Err(ModelLicensePolicyError::BoundExceeded {
            bound,
            limit,
            actual,
        }) => {
            assert_eq!(bound, "profile_name_len");
            assert_eq!(limit, MAX_PROFILE_NAME_LEN);
            assert_eq!(actual, MAX_PROFILE_NAME_LEN + 1);
        }
        other => return Err(format!("expected BoundExceeded, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_policy_name_exact_and_over_bound() -> TestResult {
    // 64 bytes is exact bound -> succeeds
    let at_bound = "P".repeat(MAX_POLICY_NAME_LEN);
    let policy = ModelLicensePolicy::new(&at_bound, ModelUseProfile::InternalEvaluation)?;
    assert_eq!(policy.policy_name(), at_bound);

    // 65 bytes is bound + 1 -> fails
    let over_bound = "P".repeat(MAX_POLICY_NAME_LEN + 1);
    let res = ModelLicensePolicy::new(&over_bound, ModelUseProfile::InternalEvaluation);
    match res {
        Err(ModelLicensePolicyError::BoundExceeded {
            bound,
            limit,
            actual,
        }) => {
            assert_eq!(bound, "policy_name_len");
            assert_eq!(limit, MAX_POLICY_NAME_LEN);
            assert_eq!(actual, MAX_POLICY_NAME_LEN + 1);
        }
        other => return Err(format!("expected BoundExceeded, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_allowed_licenses_count_exact_and_over_bound() -> TestResult {
    let mut policy = ModelLicensePolicy::new("test-policy", ModelUseProfile::InternalEvaluation)?;

    // Fill to exact bound 256
    for i in 0..MAX_POLICY_ALLOWED_LICENSES_COUNT {
        policy.allow_license(format!("LIC-{i:04}"))?;
    }
    assert_eq!(
        policy.allowed_licenses().len(),
        MAX_POLICY_ALLOWED_LICENSES_COUNT
    );

    // 257th license is bound + 1 -> fails
    let res = policy.allow_license("LIC-OVER-BOUND");
    match res {
        Err(ModelLicensePolicyError::BoundExceeded {
            bound,
            limit,
            actual,
        }) => {
            assert_eq!(bound, "allowed_licenses_count");
            assert_eq!(limit, MAX_POLICY_ALLOWED_LICENSES_COUNT);
            assert_eq!(actual, MAX_POLICY_ALLOWED_LICENSES_COUNT + 1);
        }
        other => return Err(format!("expected BoundExceeded, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_forbidden_restrictions_count_exact_and_over_bound() -> TestResult {
    let mut policy = ModelLicensePolicy::new("test-policy", ModelUseProfile::InternalEvaluation)?;

    for i in 0..MAX_POLICY_FORBIDDEN_RESTRICTIONS_COUNT {
        policy.forbid_restriction(format!("restr_{i:04}"))?;
    }
    assert_eq!(
        policy.forbidden_restrictions().len(),
        MAX_POLICY_FORBIDDEN_RESTRICTIONS_COUNT
    );

    let res = policy.forbid_restriction("restr_overflow");
    match res {
        Err(ModelLicensePolicyError::BoundExceeded {
            bound,
            limit,
            actual,
        }) => {
            assert_eq!(bound, "forbidden_restrictions_count");
            assert_eq!(limit, MAX_POLICY_FORBIDDEN_RESTRICTIONS_COUNT);
            assert_eq!(actual, MAX_POLICY_FORBIDDEN_RESTRICTIONS_COUNT + 1);
        }
        other => return Err(format!("expected BoundExceeded, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_bounds_known_terms_count_exact_and_over_bound() -> TestResult {
    let mut policy = ModelLicensePolicy::new("test-policy", ModelUseProfile::InternalEvaluation)?;

    // Policy starts with default known terms; add up to MAX_POLICY_KNOWN_TERMS_COUNT
    let current_len = policy.known_restrictions().len();
    for i in current_len..MAX_POLICY_KNOWN_TERMS_COUNT {
        policy.register_known_term(format!("term_{i:04}"))?;
    }
    assert_eq!(
        policy.known_restrictions().len(),
        MAX_POLICY_KNOWN_TERMS_COUNT
    );

    let res = policy.register_known_term("term_overflow");
    match res {
        Err(ModelLicensePolicyError::BoundExceeded {
            bound,
            limit,
            actual,
        }) => {
            assert_eq!(bound, "known_terms_count");
            assert_eq!(limit, MAX_POLICY_KNOWN_TERMS_COUNT);
            assert_eq!(actual, MAX_POLICY_KNOWN_TERMS_COUNT + 1);
        }
        other => return Err(format!("expected BoundExceeded, got {other:?}").into()),
    }

    Ok(())
}

#[test]
fn test_importer_rejects_unknown_license_at_import_time() -> TestResult {
    let dir = temp_dir("reject_unknown_license")?;
    let spool = sample_spool(&dir)?;
    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;

    let lic = sample_license_record(
        "GPL-2.0-only",
        true,
        vec!["internal_evaluation_only".to_string()],
        None,
    );
    let package = sample_package_with_license(lic)?;

    let res = importer.import_package(&package, GENERATION);
    match res {
        Err(ModelPackageError::LicensePolicy(ModelLicensePolicyError::UnknownLicense {
            spdx_or_identity,
        })) => {
            assert_eq!(spdx_or_identity, "GPL-2.0-only");
        }
        other => return Err(format!("expected LicensePolicy(UnknownLicense), got {other:?}").into()),
    }

    // Nothing was staged into the spool
    assert_eq!(importer.spool().digests().count(), 0);

    Ok(())
}

#[test]
fn test_importer_rejects_expired_license_at_import_time() -> TestResult {
    let dir = temp_dir("reject_expired_license")?;
    let spool = sample_spool(&dir)?;
    let mut policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);
    policy.set_evaluation_time(Some(TimestampNs(2_000_000_000)));

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?
        .with_license_policy(policy);

    let lic = sample_license_record(
        "Apache-2.0",
        true,
        vec!["valid_until:1000000000".to_string()],
        None,
    );
    let package = sample_package_with_license(lic)?;

    let res = importer.import_package(&package, GENERATION);
    match res {
        Err(ModelPackageError::LicensePolicy(ModelLicensePolicyError::LicenseExpired {
            expiry,
            evaluated_at,
        })) => {
            assert_eq!(expiry, TimestampNs(1_000_000_000));
            assert_eq!(evaluated_at, TimestampNs(2_000_000_000));
        }
        other => return Err(format!("expected LicensePolicy(LicenseExpired), got {other:?}").into()),
    }

    assert_eq!(importer.spool().digests().count(), 0);

    Ok(())
}

#[test]
fn test_importer_rejects_unpermitted_profile_at_import_time() -> TestResult {
    let dir = temp_dir("reject_unpermitted_profile")?;
    let spool = sample_spool(&dir)?;
    let commercial_policy =
        ModelLicensePolicy::default_for_profile(ModelUseProfile::CommercialProduction);

    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?
        .with_license_policy(commercial_policy);

    let lic = sample_license_record(
        "Apache-2.0",
        true,
        vec!["internal_evaluation_only".to_string()],
        None,
    );
    let package = sample_package_with_license(lic)?;

    let res = importer.import_package(&package, GENERATION);
    match res {
        Err(ModelPackageError::LicensePolicy(ModelLicensePolicyError::NotPermittedForUse {
            requested_profile,
            conflicting_restriction,
        })) => {
            assert_eq!(requested_profile, ModelUseProfile::CommercialProduction);
            assert_eq!(conflicting_restriction, "internal_evaluation_only");
        }
        other => return Err(format!("expected LicensePolicy(NotPermittedForUse), got {other:?}").into()),
    }

    assert_eq!(importer.spool().digests().count(), 0);

    Ok(())
}

#[test]
fn test_importer_rejects_unknown_term_at_import_time() -> TestResult {
    let dir = temp_dir("reject_unknown_term")?;
    let spool = sample_spool(&dir)?;
    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;

    let lic = sample_license_record(
        "Apache-2.0",
        true,
        vec!["arbitrary_unknown_restriction_clause".to_string()],
        None,
    );
    let package = sample_package_with_license(lic)?;

    let res = importer.import_package(&package, GENERATION);
    match res {
        Err(ModelPackageError::LicensePolicy(ModelLicensePolicyError::UnknownLicenseTerm {
            term,
        })) => {
            assert_eq!(term, "arbitrary_unknown_restriction_clause");
        }
        other => return Err(format!("expected LicensePolicy(UnknownLicenseTerm), got {other:?}").into()),
    }

    assert_eq!(importer.spool().digests().count(), 0);

    Ok(())
}

#[test]
fn test_importer_rejects_unapproved_license_at_import_time() -> TestResult {
    let dir = temp_dir("reject_unapproved_license")?;
    let spool = sample_spool(&dir)?;
    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;

    let lic = sample_license_record(
        "Apache-2.0",
        false, // Not approved!
        vec!["internal_evaluation_only".to_string()],
        None,
    );
    let package = sample_package_with_license(lic)?;

    let res = importer.import_package(&package, GENERATION);
    assert!(matches!(
        res,
        Err(ModelPackageError::LicensePolicy(
            ModelLicensePolicyError::UseNotApproved
        ))
    ));

    assert_eq!(importer.spool().digests().count(), 0);

    Ok(())
}

#[test]
fn test_importer_admits_permitted_valid_package_and_stages() -> TestResult {
    let dir = temp_dir("admit_valid_package")?;
    let spool = sample_spool(&dir)?;
    let mut importer = ModelPackageImporter::new(spool, ModelPackageLimits::default())?;

    let lic = sample_license_record(
        "Apache-2.0",
        true,
        vec!["internal_evaluation_only".to_string()],
        None,
    );
    let package = sample_package_with_license(lic)?;

    let receipt = importer.import_package(&package, GENERATION)?;
    assert_eq!(receipt.outcome, ImportOutcome::NewlyStaged);
    assert_eq!(receipt.generation.as_str(), GENERATION);

    // Spool now contains the artifacts and manifest
    assert_eq!(importer.spool().digests().count(), 4);

    Ok(())
}

#[test]
fn test_check_manifest_decision_receipt() -> TestResult {
    let policy = ModelLicensePolicy::default_for_profile(ModelUseProfile::InternalEvaluation);
    let lic = sample_license_record(
        "Apache-2.0",
        true,
        vec!["internal_evaluation_only".to_string()],
        Some(ContentDigest::sha256(b"Apache-2.0 text")),
    );
    let manifest = sample_manifest_with_license(lic)?;
    let decision: ModelLicenseDecision = policy.check_manifest(&manifest)?;

    assert_eq!(decision.admitted_spdx(), "Apache-2.0");
    assert_eq!(
        decision.target_profile(),
        &ModelUseProfile::InternalEvaluation
    );
    assert_eq!(decision.evaluated_at(), None);
    assert_eq!(decision.verified_restrictions_count(), 1);
    assert_ne!(decision.decision_digest(), ContentDigest::sha256(b""));

    Ok(())
}
