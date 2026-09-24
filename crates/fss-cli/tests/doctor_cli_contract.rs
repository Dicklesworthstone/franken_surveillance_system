#![forbid(unsafe_code)]
//! Contract tests for `fss doctor` command-line execution (fss-2h5zq.57, CAP- DOCTOR).
//!
//! Verifies:
//! 1. `fss doctor --json` without `--root` keeps the `design_only` output byte for byte and exits 0.
//! 2. With `--root`, stdout is exactly the library report of the same root, and the exit code is
//!    0 (healthy), 3 (attention_required), or 4 (not_a_deployment), in process and through the
//!    real `fss` binary.
//! 3. Argument errors (missing `--json`, missing or duplicate `--root`) exit 2 with empty stdout.

use std::error::Error;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use fss_cli::{DoctorArgs, ExitIdentity, FssCommand, execute_fss_with_exit, parse_fss_args};
use fss_core::{ContentDigest, OperationId, RootAuthoritySpec};
use fss_reference::doctor::inspect_deployment;
use fss_reference::{
    ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority,
    reference_deployment::RELATIVE_PATH_LEDGER,
};

type TestResult = Result<(), Box<dyn Error>>;

const LINEAGE: &str = "site:doctor-cli-contract";

/// Scopes fixture paths to this test process: concurrent `cargo test` runs that share a target
/// directory share `CARGO_TARGET_TMPDIR`, and a fixed path would let one run remove or lock another
/// run's live deployment.
fn fresh(name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("doctor_cli_contract-{}", std::process::id()))
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
    let scratch_root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("doctor_cli_contract_cx-{}", std::process::id()))
        .join(label);
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

fn append_incomplete_tail(dep: &Path) -> TestResult {
    OpenOptions::new()
        .append(true)
        .open(dep.join(RELATIVE_PATH_LEDGER))?
        .write_all(b"FSSJRN01")?;
    Ok(())
}

fn doctor(root: &Path) -> (String, ExitIdentity) {
    execute_fss_with_exit(FssCommand::Doctor(DoctorArgs {
        root: Some(root.to_path_buf()),
    }))
}

fn run_fss(args: &[OsString]) -> Result<(Option<i32>, String, String), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(args)
        .output()?;
    Ok((
        output.status.code(),
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?,
    ))
}

fn root_args(root: &Path) -> Vec<OsString> {
    vec![
        OsString::from("doctor"),
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
    ]
}

/// Serializes this binary's tests. Tests open a `ReferenceDeployment` in this process, which holds
/// its native flock owner lock, and spawn real CLI processes. A child spawned by a concurrent test
/// thread inherits, until its exec closes it, every descriptor open at that instant, including
/// another test's held deployment lock; the flock then outlives its owner's drop, and that test's
/// next child or read-only inspection sees the deployment as Locked or as having an active writer.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn test_doctor_without_root_retains_design_only_byte_for_byte() -> TestResult {
    let _serial = serial();
    let (stdout, exit_id) = execute_fss_with_exit(FssCommand::Doctor(DoctorArgs { root: None }));
    assert_eq!(exit_id, ExitIdentity::SUCCESS);
    let expected = format!(
        "{{\"schema\":\"fss.doctor.v1\",\"version\":\"{}\",\"verdict\":\"design_only\",\"checks\":[{{\"id\":\"core.contracts\",\"status\":\"present\"}},{{\"id\":\"runtime.acquisition\",\"status\":\"not_implemented\"}},{{\"id\":\"release.qualification\",\"status\":\"not_qualified\"}}]}}",
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(stdout, expected);

    let (code, out, err) = run_fss(&[OsString::from("doctor"), OsString::from("--json")])?;
    assert_eq!(code, Some(0));
    assert_eq!(out, format!("{expected}\n"));
    assert_eq!(err, "");
    Ok(())
}

#[test]
fn test_doctor_in_process_exit_codes_match_the_library_report() -> TestResult {
    let _serial = serial();
    let clean = init_clean_deployment("clean")?;
    let (stdout, exit_id) = doctor(&clean);
    assert_eq!(stdout, inspect_deployment(&clean).to_json());
    assert_eq!(exit_id, ExitIdentity::SUCCESS);

    let attention = init_clean_deployment("incomplete")?;
    append_incomplete_tail(&attention)?;
    let (stdout, exit_id) = doctor(&attention);
    assert_eq!(stdout, inspect_deployment(&attention).to_json());
    assert_eq!(exit_id, ExitIdentity::DOCTOR_ATTENTION_REQUIRED);
    assert_eq!(exit_id.code, 3);

    let empty = fresh("empty")?;
    let (stdout, exit_id) = doctor(&empty);
    assert_eq!(stdout, inspect_deployment(&empty).to_json());
    assert_eq!(exit_id, ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT);
    assert_eq!(exit_id.code, 4);

    let missing = empty.join("missing");
    let (stdout, exit_id) = doctor(&missing);
    assert_eq!(stdout, inspect_deployment(&missing).to_json());
    assert_eq!(exit_id, ExitIdentity::DOCTOR_NOT_A_DEPLOYMENT);
    Ok(())
}

#[test]
fn test_real_fss_binary_with_root_prints_the_report_and_exit_code() -> TestResult {
    let _serial = serial();
    let clean = init_clean_deployment("binary_clean")?;
    let (code, out, err) = run_fss(&root_args(&clean))?;
    assert_eq!(code, Some(0));
    assert_eq!(out, format!("{}\n", inspect_deployment(&clean).to_json()));
    assert_eq!(err, "");

    let mut equals_form = vec![OsString::from("doctor")];
    let mut root_flag = OsString::from("--root=");
    root_flag.push(clean.as_os_str());
    equals_form.push(root_flag);
    equals_form.push(OsString::from("--json"));
    let (code, out_equals, _) = run_fss(&equals_form)?;
    assert_eq!(code, Some(0));
    assert_eq!(out_equals, out);

    let attention = init_clean_deployment("binary_incomplete")?;
    append_incomplete_tail(&attention)?;
    let (code, out, err) = run_fss(&root_args(&attention))?;
    assert_eq!(code, Some(3));
    assert_eq!(
        out,
        format!("{}\n", inspect_deployment(&attention).to_json())
    );
    assert_eq!(err, "");

    let empty = fresh("binary_empty")?;
    let (code, out, err) = run_fss(&root_args(&empty))?;
    assert_eq!(code, Some(4));
    assert_eq!(out, format!("{}\n", inspect_deployment(&empty).to_json()));
    assert_eq!(err, "");

    for args in [
        vec![
            OsString::from("doctor"),
            OsString::from("--root"),
            empty.as_os_str().to_owned(),
        ],
        vec![
            OsString::from("doctor"),
            OsString::from("--json"),
            OsString::from("--root"),
        ],
        {
            let mut twice = root_args(&empty);
            twice.push(OsString::from("--root"));
            twice.push(empty.as_os_str().to_owned());
            twice
        },
    ] {
        let (code, out, err) = run_fss(&args)?;
        assert_eq!(code, Some(2), "args {args:?}");
        assert_eq!(
            out, "",
            "stdout must be empty on an argument error: {args:?}"
        );
        assert!(err.starts_with("fss: error[ERR-CLI-"), "stderr: {err}");
    }
    Ok(())
}

#[test]
fn test_doctor_cli_parsing_coverage() -> TestResult {
    let _serial = serial();
    let parse = |args: &[&str]| parse_fss_args(args.iter().map(OsString::from));
    assert_eq!(
        parse(&["doctor", "--json"]).ok(),
        Some(FssCommand::Doctor(DoctorArgs { root: None }))
    );
    assert_eq!(
        parse(&["doctor", "--json", "--root", "/deploy/root"]).ok(),
        Some(FssCommand::Doctor(DoctorArgs {
            root: Some(PathBuf::from("/deploy/root")),
        }))
    );
    assert_eq!(
        parse(&["doctor", "--root=/deploy/root", "--json"]).ok(),
        Some(FssCommand::Doctor(DoctorArgs {
            root: Some(PathBuf::from("/deploy/root")),
        }))
    );
    assert!(
        parse(&["doctor"]).is_err(),
        "doctor without --json must fail"
    );
    assert!(parse(&["doctor", "--json", "--root"]).is_err());
    assert!(parse(&["doctor", "--json", "--root="]).is_err());
    assert!(parse(&["doctor", "--json", "--root", "/a", "--root", "/b"]).is_err());
    assert!(parse(&["doctor", "--json", "--json"]).is_err());
    assert!(parse(&["doctor", "--json", "extra"]).is_err());
    Ok(())
}
