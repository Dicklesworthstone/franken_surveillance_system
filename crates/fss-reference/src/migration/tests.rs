#![forbid(unsafe_code)]
//! Unit tests for v1-to-v2 deployment layout parsing, format detection, refusal guidance, and
//! canonical receipt digests.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{ContentDigest, LedgerAnchor};

use super::{
    DEPLOYMENT_LAYOUT_V2_FORMAT_VERSION, DEPLOYMENT_LAYOUT_V2_SCHEMA, DeploymentFormatVersion,
    DeploymentLayoutV2, ERR_DEPLOYMENT_FORMAT_V1_001, MIGRATE_INCOMPLETE_FILENAME,
    MIGRATION_RECEIPT_SCHEMA, MigrationEquivalenceReceipt, MigrationError,
    detect_deployment_format, require_v2_deployment, v1_format_refusal_guidance,
};
use crate::reference_deployment::{DeploymentLayout, DeploymentLimits};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-migration-unit-{tag}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err("could not allocate temp directory".into())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn v2_layout_canonical_roundtrip_and_strict_rejection() -> TestResult {
    let limits_digest = DeploymentLimits::standard().canonical_digest()?;
    let layout = DeploymentLayoutV2::new("site:mig-unit", limits_digest);
    assert_eq!(layout.schema, DEPLOYMENT_LAYOUT_V2_SCHEMA);
    assert_eq!(layout.format_version, DEPLOYMENT_LAYOUT_V2_FORMAT_VERSION);

    let text = layout.to_canonical_text();
    let parsed = DeploymentLayoutV2::parse_canonical_text(&text)?;
    assert_eq!(parsed, layout);

    // Non-canonical line order must be rejected.
    let reordered: String = text.lines().rev().map(|l| format!("{l}\n")).collect();
    assert!(DeploymentLayoutV2::parse_canonical_text(&reordered).is_err());

    // Wrong version must be rejected.
    let wrong_ver = text.replace("version=2", "version=1");
    assert!(DeploymentLayoutV2::parse_canonical_text(&wrong_ver).is_err());
    Ok(())
}

#[test]
fn detect_format_distinguishes_v1_v2_incomplete_and_non_deployment() -> TestResult {
    let temp = TempDir::new("detect")?;
    let limits_digest = DeploymentLimits::standard().canonical_digest()?;

    // Missing directory -> NotADeployment.
    let missing = temp.0.join("missing");
    assert!(matches!(
        detect_deployment_format(&missing)?,
        DeploymentFormatVersion::NotADeployment { .. }
    ));

    // Empty dir without LAYOUT -> NotADeployment.
    let empty = temp.0.join("empty");
    fs::create_dir(&empty)?;
    assert!(matches!(
        detect_deployment_format(&empty)?,
        DeploymentFormatVersion::NotADeployment { .. }
    ));

    // v1 LAYOUT -> V1 + ERR-DEPLOYMENT-FORMAT-V1-001 guidance.
    let v1_dir = temp.0.join("v1");
    fs::create_dir(&v1_dir)?;
    let v1_layout = DeploymentLayout::new("site:v1-unit", limits_digest);
    fs::write(v1_dir.join("LAYOUT"), v1_layout.to_canonical_text())?;
    assert!(matches!(
        detect_deployment_format(&v1_dir)?,
        DeploymentFormatVersion::V1 { .. }
    ));
    let refused = require_v2_deployment(&v1_dir);
    assert!(matches!(
        refused,
        Err(MigrationError::UnsupportedV1Format(ref g))
            if g.error_id == ERR_DEPLOYMENT_FORMAT_V1_001
                && g.migrate_command.contains("fss migrate --from")
                && g.migrate_command.contains("--to")
    ));

    // v2 LAYOUT + ledger/epochs -> V2.
    let v2_dir = temp.0.join("v2");
    fs::create_dir_all(v2_dir.join("ledger/epochs"))?;
    let v2_layout = DeploymentLayoutV2::new("site:v2-unit", limits_digest);
    fs::write(v2_dir.join("LAYOUT"), v2_layout.to_canonical_text())?;
    assert!(matches!(
        detect_deployment_format(&v2_dir)?,
        DeploymentFormatVersion::V2 { .. }
    ));
    assert_eq!(require_v2_deployment(&v2_dir)?, v2_layout);

    // Adding `.migrate-incomplete` overrides even a valid v2 LAYOUT!
    fs::write(
        v2_dir.join(MIGRATE_INCOMPLETE_FILENAME),
        "fss.deployment_migrate.incomplete.v1\n",
    )?;
    assert!(matches!(
        detect_deployment_format(&v2_dir)?,
        DeploymentFormatVersion::MigrateIncomplete { .. }
    ));
    assert!(matches!(
        require_v2_deployment(&v2_dir),
        Err(MigrationError::IncompleteMigration { .. })
    ));
    Ok(())
}

#[test]
fn refusal_guidance_and_receipt_digest_are_deterministic_and_tamper_evident() -> TestResult {
    let guidance = v1_format_refusal_guidance(
        PathBuf::from("/var/fss/old-v1").as_path(),
        Some(PathBuf::from("/var/fss/new-v2").as_path()),
    );
    assert_eq!(guidance.error_id, ERR_DEPLOYMENT_FORMAT_V1_001);
    assert_eq!(
        guidance.migrate_command,
        "fss migrate --from /var/fss/old-v1 --to /var/fss/new-v2"
    );
    let gjson = guidance.to_json();
    assert!(gjson.contains(ERR_DEPLOYMENT_FORMAT_V1_001));
    assert!(gjson.contains("fss migrate --from /var/fss/old-v1 --to /var/fss/new-v2"));

    let mut source_anchor = LedgerAnchor::genesis("site:receipt-unit");
    source_anchor.commit_sequence = 5;
    let mut dest_anchor = source_anchor.clone();
    dest_anchor.state_root = ContentDigest::sha256(b"v2-merkle");
    let mut receipt = MigrationEquivalenceReceipt {
        schema: MIGRATION_RECEIPT_SCHEMA.to_owned(),
        site_lineage: "site:receipt-unit".to_owned(),
        source_v1_anchor: source_anchor,
        source_v1_ledger_root: ContentDigest::sha256(b"v1-root"),
        dest_v2_merkle_root: dest_anchor.state_root,
        dest_v2_anchor: dest_anchor,
        dest_v2_history_root: ContentDigest::sha256(b"v2-history"),
        batches_migrated: 5,
        objects_migrated: 12,
        roots_migrated: 2,
        events_migrated: 1,
        holds_migrated: 1,
        masks_migrated: 1,
        tombstones_migrated: 1,
        source_unreferenced_orphans: vec![ContentDigest::sha256(b"orphan-1")],
        effects_verified: true,
        effects_journal_digest: Some(ContentDigest::sha256(b"effects")),
        agent_files_verified: 0,
        projection_state_digest: ContentDigest::sha256(b"proj"),
        semantic_equivalence_verified: true,
        receipt_digest: ContentDigest::sha256(b"placeholder"),
    };
    receipt.receipt_digest = receipt.compute_digest()?;
    receipt.verify_self_digest()?;

    let json = receipt.to_json();
    assert!(json.contains("\"schema\":\"fss.migration_receipt.v1\""));
    assert!(json.contains("\"semantic_equivalence_verified\":true"));
    assert!(json.contains(&receipt.receipt_digest.to_text()));

    // Tampering any field must invalidate self-digest verification.
    receipt.batches_migrated = 6;
    assert!(receipt.verify_self_digest().is_err());
    Ok(())
}
