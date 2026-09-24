#![forbid(unsafe_code)]
//! Separate CLI invocations use real source/recipe custody and the shared native fixture.
#[path = "../../fss-reference/tests/reconstruction_operation/support.rs"]
mod fixture;
use fixture::*;
use fss_cli::ExitIdentity;
use fss_core::ContentDigest;
use fss_publication::NeverCancel;
use fss_reference::rtsp::recording_recipe::storage::operation::*;
use std::ffi::OsString;
use std::process::{Command, Output};

fn args(f: &Fixture, command: &str) -> Test<Vec<OsString>> {
    let scope = source_scope()?;
    let mut result: Vec<OsString> = vec![
        command.into(),
        "--root".into(),
        f.path.as_os_str().to_owned(),
        "--recipe-id".into(),
        f.pin.recipe.to_text().into(),
        "--recipe-root".into(),
        f.pin.root.to_text().into(),
        "--ingress".into(),
        source::KEY.ingress.to_string().into(),
        "--generation".into(),
        source::KEY.generation.to_string().into(),
        "--ssrc".into(),
        source::KEY.ssrc.to_string().into(),
        "--peer".into(),
        "127.0.0.1:554".into(),
        "--authority".into(),
        "camera.local".into(),
        "--rtp-channel".into(),
        "0".into(),
        "--rtcp-channel".into(),
        "1".into(),
        "--receive-clock".into(),
        scope.receive_clock.to_text().into(),
        "--retention-evidence".into(),
        scope.retention_evidence.to_text().into(),
        "--max-object-bytes".into(),
        "1048576".into(),
    ];
    if command == "reconstruct-recipe" {
        result.extend(["--commit".into(), "yes".into()]);
    }
    Ok(result)
}
fn run(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive"))
        .args(args)
        .output()?)
}
fn success(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.len() < 8192);
    assert!(text.ends_with("}\n"));
    assert!(text.contains("\"operation_complete\":true"));
    assert!(text.contains("\"capture_complete\":false"));
    assert!(text.contains("\"archive_index_published\":false"));
    assert!(text.contains("\"source_bytes_emitted\":false"));
    assert!(!text.contains("camera.local"));
    assert!(!text.contains("camera-password"));
    Ok(text)
}
fn replace(args: &mut [OsString], key: &str, value: OsString) -> Test {
    let at = args
        .iter()
        .position(|v| v.as_os_str() == std::ffi::OsStr::new(key))
        .ok_or("missing test option")?;
    args[at + 1] = value;
    Ok(())
}
/// Serializes this binary's tests. Every test holds native flock owner locks in this process and
/// spawns real CLI processes. A child spawned by a concurrent test thread inherits, until its exec
/// closes it, every descriptor open at that instant, including another test's held owner lock; the
/// flock then outlives its owner's drop, and that test's next open or child sees Locked/Busy.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
#[test]
fn check_then_reconstruct_then_lost_stdout_retry_has_identical_api_result_root() -> Test {
    let _serial = serial();
    let f = seed("cli-cold", 2, false, false)?;
    let (candidate, initial_count) = {
        let p = open(&f.path)?;
        let loaded = load(&f, &p)?;
        let plan = PreparedReconstruction::prepare(
            &loaded,
            &p,
            bounds(),
            ReconstructionLimits::default(),
            &Clock(1000),
            &NeverCancel,
            &mut work(),
        )?;
        (plan.pin().clone(), p.visible_roots().count())
    };
    let checked = success(run(&args(&f, "check-recipe")?)?)?;
    assert!(checked.contains("\"result_status\":\"not_requested\""));
    assert!(checked.contains(&candidate.root.to_text()));
    {
        let p = open(&f.path)?;
        assert_eq!(p.visible_roots().count(), initial_count);
    }
    let command = args(&f, "reconstruct-recipe")?;
    let published = success(run(&command)?)?;
    assert!(published.contains("\"result_status\":\"published\""));
    assert!(published.contains("\"new_windows\":2"));
    drop(published); // The next process has only the original stored recipe, not this reply.
    let repeated = success(run(&command)?)?;
    assert!(repeated.contains("\"result_status\":\"already_durable\""));
    assert!(repeated.contains("\"new_windows\":0"));
    assert!(repeated.contains("\"reused_windows\":2"));
    let p = open(&f.path)?;
    assert_eq!(
        p.root(&candidate.slot).ok_or("result root missing")?.root,
        candidate.root
    );
    assert_eq!(p.visible_roots().count(), initial_count + 3);
    Ok(())
}
#[test]
fn incomplete_fragment_is_reported_without_a_fabricated_output_recording() -> Test {
    let _serial = serial();
    let f = seed("cli-fragment", 0, false, true)?;
    let result = success(run(&args(&f, "reconstruct-recipe")?)?)?;
    assert!(result.contains("\"windows\":0"));
    assert!(!result.contains("\"fragment_bytes\":0"));
    Ok(())
}
#[test]
fn wrong_late_recipe_never_publishes_earlier_valid_windows() -> Test {
    let _serial = serial();
    let f = seed("cli-late-mismatch", 3, true, false)?;
    let count = open(&f.path)?.visible_roots().count();
    let out = run(&args(&f, "reconstruct-recipe")?)?;
    assert_eq!(
        out.status.code(),
        Some(i32::from(ExitIdentity::RUNTIME_FAILURE.code))
    );
    assert!(out.stdout.is_empty());
    assert_eq!(open(&f.path)?.visible_roots().count(), count);
    Ok(())
}
#[test]
fn explicit_commit_is_required_and_check_rejects_mutation_flags() -> Test {
    let _serial = serial();
    let f = seed("cli-consent", 1, false, false)?;
    let mut command = args(&f, "reconstruct-recipe")?;
    command.truncate(command.len() - 2);
    let out = run(&command)?;
    assert!(out.stdout.is_empty());
    assert_eq!(
        out.status.code(),
        Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
    );
    let mut command = args(&f, "check-recipe")?;
    command.extend(["--commit".into(), "yes".into()]);
    let out = run(&command)?;
    assert!(out.stdout.is_empty());
    assert_eq!(
        out.status.code(),
        Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
    );
    Ok(())
}
#[test]
fn changed_scope_and_tighter_execution_bounds_refuse_before_publication() -> Test {
    let _serial = serial();
    let f = seed("cli-limits", 1, false, false)?;
    let count = open(&f.path)?.visible_roots().count();
    let mut wrong = args(&f, "reconstruct-recipe")?;
    replace(
        &mut wrong,
        "--receive-clock",
        ContentDigest::sha256(b"different clock").to_text().into(),
    )?;
    assert!(!run(&wrong)?.status.success());
    for bound in ["--max-work", "--max-output-bytes", "--max-steps"] {
        let mut command = args(&f, "reconstruct-recipe")?;
        command.extend([bound.into(), "1".into()]);
        let out = run(&command)?;
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }
    assert_eq!(open(&f.path)?.visible_roots().count(), count);
    Ok(())
}
#[test]
fn missing_archive_is_not_created_and_unknown_secret_values_are_not_echoed() -> Test {
    let _serial = serial();
    let f = seed("cli-missing", 1, false, false)?;
    let missing = f.path.join("never-create-this-owner");
    let mut command = args(&f, "check-recipe")?;
    replace(&mut command, "--root", missing.as_os_str().to_owned())?;
    let out = run(&command)?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!missing.exists());
    let out = run(&[
        "reconstruct-recipe".into(),
        "--password".into(),
        "PRIVATE_OPERATOR_SENTINEL".into(),
    ])?;
    assert!(!out.status.success());
    assert!(!String::from_utf8(out.stderr)?.contains("PRIVATE_OPERATOR_SENTINEL"));
    Ok(())
}
#[test]
fn held_native_owner_lock_blocks_the_other_process_without_repair() -> Test {
    let _serial = serial();
    let f = seed("cli-lock", 1, false, false)?;
    let p = open(&f.path)?;
    let before = p.visible_roots().count();
    let out = run(&args(&f, "reconstruct-recipe")?)?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(p.visible_roots().count(), before);
    Ok(())
}
#[test]
fn duplicate_overflow_and_incomplete_options_fail_before_storage() -> Test {
    let _serial = serial();
    let f = seed("cli-args", 1, false, false)?;
    for extra in [
        vec!["--recipe-id", "other"],
        vec!["--max-work", "18446744073709551616"],
        vec!["--max-windows", "0"],
        vec!["--timeout-ms"],
        vec!["--max-steps", "-1"],
    ] {
        let mut command = args(&f, "check-recipe")?;
        command.extend(extra.into_iter().map(OsString::from));
        let out = run(&command)?;
        assert!(out.stdout.is_empty());
        assert_eq!(
            out.status.code(),
            Some(i32::from(ExitIdentity::MALFORMED_VALUE.code))
        );
    }
    let help = run(&["help".into()])?;
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout)?.contains("check-recipe|reconstruct-recipe"));
    Ok(())
}
#[cfg(unix)]
#[test]
fn symlink_archive_root_is_not_followed() -> Test {
    let _serial = serial();
    let f = seed("cli-symlink", 1, false, false)?;
    let alias = f.path.with_extension("alias");
    std::os::unix::fs::symlink(&f.path, &alias)?;
    let mut command = args(&f, "reconstruct-recipe")?;
    replace(&mut command, "--root", alias.as_os_str().to_owned())?;
    let out = run(&command)?;
    std::fs::remove_file(alias)?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    Ok(())
}
