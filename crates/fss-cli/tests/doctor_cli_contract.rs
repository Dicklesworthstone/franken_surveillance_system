#![forbid(unsafe_code)]
//! Contract tests for `fss doctor` command-line execution (fss-2h5zq.57 / CAP- DOCTOR).
//!
//! Verifies:
//! 1. `fss doctor --json` without `--root` retains existing `design_only` skeleton byte-for-byte and exits 0.
//! 2. `fss doctor --json --root <clean>` executes doctor on deployment and exits 0.
//! 3. `fss doctor --json --root <incomplete>` reports attention required and exits 3.
//! 4. `fss doctor --json --root <not_a_deployment>` reports not a deployment and exits 4.
//! 5. CLI argument parsing failures (missing `--json`, duplicate options) exit 2.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fss_cli::{DoctorArgs, ExitIdentity, FssCommand, execute_fss_with_exit, parse_fss_args};
use fss_core::{ContentDigest, OperationId, RootAuthoritySpec};
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority,
    reference_deployment::RELATIVE_PATH_LEDGER,
};

type TestResult = Result<(), Box<dyn Error>>;

const LINEAGE: &str = "site:doctor-cli-contract";

fn fresh(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("doctor_cli_contract")
        .join(name);
    match fs::remove_dir_all(&base) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(&base)?;
    Ok(base)
}

fn test_cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:test-{label}"),
        operation_id: OperationId::parse(format!("operation:test-{label}"))?,
        principal: format!("operator:test-{label}"),
        capabilities: vec![ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: fss_core::BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"test-anchor-universe"),
        generation: 1,
    };
    let root_auth = fss_core::ContextAuthority::new_root(spec)?;
    let scratch_root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!(
            "test-replay-cx-cli-doc-{label}-{}",
            std::process::id()
        ));
    let io = ReplayIoAuthority::from_context_authority(&root_auth, scratch_root)?;
    Ok(ReplayCx::new(io))
}

fn init_clean_deployment(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = fresh(name)?;
    let cx = test_cx(name)?;
    let dep = ReferenceDeployment::open(&base, LINEAGE, &cx)?;
    drop(dep);
    Ok(base)
}

#[test]
fn test_doctor_without_root_retains_design_only_byte_for_byte() -> TestResult {
    let (stdout, exit_id) = execute_fss_with_exit(FssCommand::Doctor(DoctorArgs { root: None }));
    assert_eq!(exit_id, ExitIdentity::SUCCESS);
    assert_eq!(exit_id.code, 0);

    let expected = format!(
        "{{\"schema\":\"fss.doctor.v1\",\"version\":\"{}\",\"verdict\":\"design_only\",\"checks\":[{{\"id\":\"core.contracts\",\"status\":\"present\"}},{{\"id\":\"runtime.acquisition\",\"status\":\"not_implemented\"}},{{\"id\":\"release.qualification\",\"status\":\"not_qualified\"}}]}}",
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        stdout, expected,
        "doctor without root must retain byte-for-byte exact design_only output"
    );
    Ok(())
}

#[test]
fn test_doctor_with_clean_root_exits_0() -> TestResult {
    let dep = init_clean_deployment("clean")?;
    let (stdout, exit_id) = execute_fss_with_exit(FssCommand::Doctor(DoctorArgs {
        root: Some(dep.clone()),
    }));
    assert_eq!(exit_id, ExitIdentity::SUCCESS);
    assert_eq!(exit_id.code, 0);
    assert!(stdout.contains("\"verdict\":\"healthy\""));
    assert!(stdout.contains(&dep.display().to_string()));
    Ok(())
}

#[test]
fn test_doctor_with_incomplete_tail_exits_3() -> TestResult {
    let dep = init_clean_deployment("incomplete")?;
    let ledger_path = dep.join(RELATIVE_PATH_LEDGER);

    // Append incomplete record tail (valid RECORD_MAGIC prefix without complete record body)
    let mut file = OpenOptions::new().append(true).open(&ledger_path)?;
    file.write_all(b"FSSJRN01")?;

    let (stdout, exit_id) = execute_fss_with_exit(FssCommand::Doctor(DoctorArgs {
        root: Some(dep.clone()),
    }));
    assert_eq!(exit_id, ExitIdentity::DOCTOR_ATTENTION_REQUIRED);
    assert_eq!(exit_id.code, 3);
    assert!(stdout.contains("\"verdict\":\"attention_required\""));
    assert!(stdout.contains("--truncate-incomplete-tail ledger"));
    Ok(())
}

#[test]
fn test_doctor_with_not_a_deployment_exits_4() -> TestResult {
    let empty_dir = fresh("empty")?;
    let (stdout, exit_id) = execute_fss_with_exit(FssCommand::Doctor(DoctorArgs {
        root: Some(empty_dir),
    }));
    assert_eq!(exit_id, ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT);
    assert_eq!(exit_id.code, 4);
    assert!(stdout.contains("\"verdict\":\"not_a_deployment\""));

    let non_existent = PathBuf::from("/path/that/does/not/exist/fss_doctor_test");
    let (stdout_non_existent, exit_id_non_existent) =
        execute_fss_with_exit(FssCommand::Doctor(DoctorArgs {
            root: Some(non_existent),
        }));
    assert_eq!(exit_id_non_existent, ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT);
    assert_eq!(exit_id_non_existent.code, 4);
    assert!(stdout_non_existent.contains("\"verdict\":\"not_a_deployment\""));
    Ok(())
}

#[test]
fn test_doctor_cli_parsing_coverage() -> TestResult {
    // Valid command forms
    assert_eq!(
        parse_fss_args([
            std::ffi::OsString::from("doctor"),
            std::ffi::OsString::from("--json"),
        ])
        .ok(),
        Some(FssCommand::Doctor(DoctorArgs { root: None }))
    );

    assert_eq!(
        parse_fss_args([
            std::ffi::OsString::from("doctor"),
            std::ffi::OsString::from("--json"),
            std::ffi::OsString::from("--root"),
            std::ffi::OsString::from("/test/path"),
        ])
        .ok(),
        Some(FssCommand::Doctor(DoctorArgs {
            root: Some(PathBuf::from("/test/path")),
        }))
    );

    assert_eq!(
        parse_fss_args([
            std::ffi::OsString::from("doctor"),
            std::ffi::OsString::from("--root=/test/path"),
            std::ffi::OsString::from("--json"),
        ])
        .ok(),
        Some(FssCommand::Doctor(DoctorArgs {
            root: Some(PathBuf::from("/test/path")),
        }))
    );

    // Missing --json
    assert!(
        parse_fss_args([std::ffi::OsString::from("doctor")]).is_err(),
        "doctor without --json must fail"
    );

    // Missing value for --root
    assert!(
        parse_fss_args([
            std::ffi::OsString::from("doctor"),
            std::ffi::OsString::from("--json"),
            std::ffi::OsString::from("--root"),
        ])
        .is_err(),
        "doctor --root without value must fail"
    );

    // Duplicate --root
    assert!(
        parse_fss_args([
            std::ffi::OsString::from("doctor"),
            std::ffi::OsString::from("--json"),
            std::ffi::OsString::from("--root"),
            std::ffi::OsString::from("/a"),
            std::ffi::OsString::from("--root"),
            std::ffi::OsString::from("/b"),
        ])
        .is_err(),
        "duplicate --root must fail"
    );

    // Duplicate --json
    assert!(
        parse_fss_args([
            std::ffi::OsString::from("doctor"),
            std::ffi::OsString::from("--json"),
            std::ffi::OsString::from("--json"),
        ])
        .is_err(),
        "duplicate --json must fail"
    );

    Ok(())
}
