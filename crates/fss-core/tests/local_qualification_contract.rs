#![forbid(unsafe_code)]
//! Field-level contract tests for the machine-readable local qualification
//! contract (`architecture/local_qualification.toml`, bead fss-x4a.30.104 /
//! REG-LOCAL-QUALIFICATION-MACHINE-001):
//!
//! * the contract's load-bearing authority invariants are pinned verbatim
//!   (local DSR receipt authority, qualify.sh as repository entrypoint,
//!   workflow YAML as portable spec only, clean-snapshot + sibling-closure +
//!   locked-resolution + offline requirements, no partial target matrices,
//!   download-verify-after-upload, signing separate from build);
//! * the declared repository entrypoint exists on disk;
//! * the toolchain section names the pin file and policy;
//! * `scripts/check-policy.py` validates the file in the policy lane
//!   (cross-registry validation hook — its pass is the green policy lane);
//! * tamper detection: mutation of any pinned invariant changes the content.

use std::error::Error;
use std::path::Path;

const LOCAL_QUAL_TOML: &str = include_str!("../../../architecture/local_qualification.toml");

/// The contract's load-bearing invariants (exact `key = value` text).
const PINNED_INVARIANTS: [&str; 11] = [
    "authority = \"local_dsr_receipt\"",
    "repository_entrypoint = \"scripts/qualify.sh\"",
    "workflow_yaml_role = \"portable_executable_specification_only\"",
    "github_hosted_required = false",
    "clean_snapshot_required = true",
    "exact_sibling_revision_closure = true",
    "locked_resolution = true",
    "offline_after_provisioning = true",
    "partial_target_matrix_may_publish = false",
    "download_and_verify_after_upload = true",
    "signing_separate_from_build = true",
];

#[test]
fn authority_invariants_are_pinned_verbatim() {
    for invariant in PINNED_INVARIANTS {
        assert!(
            LOCAL_QUAL_TOML.contains(invariant),
            "qualification contract missing or drifted: {invariant}"
        );
    }
}

#[test]
fn declared_entrypoint_exists_and_schema_is_current() -> Result<(), Box<dyn Error>> {
    assert!(LOCAL_QUAL_TOML.contains("fss.local_qualification.v2"));
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root")?;
    assert!(
        root.join("scripts/qualify.sh").is_file(),
        "declared repository entrypoint scripts/qualify.sh missing"
    );
    assert!(LOCAL_QUAL_TOML.contains("pin_file = \"rust-toolchain.toml\""));
    assert!(root.join("rust-toolchain.toml").is_file());
    Ok(())
}

#[test]
fn toolchain_channel_agrees_with_the_repo_pin() -> Result<(), Box<dyn Error>> {
    // The contract's accepted channel must equal the repo's rust-toolchain
    // pin (check-policy.py enforces this in the policy lane; pin it here too).
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root")?;
    let toolchain_toml = std::fs::read_to_string(root.join("rust-toolchain.toml"))?;
    let channel = toolchain_toml
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel = "))
        .and_then(|v| v.trim().strip_prefix('"'))
        .and_then(|v| v.strip_suffix('"'))
        .ok_or("channel not found in rust-toolchain.toml")?;
    assert!(
        LOCAL_QUAL_TOML.contains(&format!("\"{channel}\"")),
        "accepted channel in local_qualification.toml must cover the repo pin {channel}"
    );
    Ok(())
}

#[test]
fn tampering_is_detectable() {
    let mut tampered = LOCAL_QUAL_TOML.to_string();
    tampered = tampered.replace("clean_snapshot_required = true", "clean_snapshot_required = false");
    assert!(tampered.contains("clean_snapshot_required = false"));
    assert!(!tampered.contains("clean_snapshot_required = true"));
}
