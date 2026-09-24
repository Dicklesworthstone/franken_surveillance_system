#![forbid(unsafe_code)]
//! Process restart and continued capture do not invalidate an independently selected recipe.
#[path = "../../fss-reference/tests/historical_recipe_support/mod.rs"]
mod fixture;
use fixture::*;
use std::ffi::OsString;
use std::process::{Command, Output};
use fss_cli::ExitIdentity;

fn args(f: &Fixture, publish: bool) -> Test<Vec<OsString>> {
    let scope = source_scope()?; let key = scope.binding.key();
    let mut a = vec![if publish { "reconstruct-recipe".into() } else { "check-recipe".into() },
        "--root".into(), f.path.as_os_str().to_owned(),
        "--recipe-id".into(), f.pin.recipe.to_text().into(), "--recipe-root".into(), f.pin.root.to_text().into(),
        "--ingress".into(), key.ingress.to_string().into(), "--generation".into(), key.generation.to_string().into(),
        "--ssrc".into(), key.ssrc.to_string().into(), "--peer".into(), scope.binding.peer().to_string().into(),
        "--authority".into(), scope.binding.authority().into(),
        "--rtp-channel".into(), scope.channels.0.to_string().into(), "--rtcp-channel".into(), scope.channels.1.to_string().into(),
        "--receive-clock".into(), scope.receive_clock.to_text().into(),
        "--retention-evidence".into(), scope.retention_evidence.to_text().into(),
        "--timeout-ms".into(), "300000".into()];
    if publish { a.extend(["--commit".into(), "yes".into()]); }
    Ok(a)
}
fn run(a: Vec<OsString>) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-archive")).args(a).output()?)
}
fn success(out: Output) -> Test<String> {
    assert!(out.status.success(), "recipe command failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(out.stderr.is_empty());
    let text = String::from_utf8(out.stdout)?;
    assert!(text.len() <= 8192); assert!(text.contains("\"capture_complete\":false"));
    assert!(text.contains("\"source_bytes_emitted\":false"));
    assert!(text.contains("\"archive_index_published\":false"));
    assert!(text.contains("\"operation_complete\":true"));
    Ok(text)
}
fn field<'a>(text: &'a str, name: &str) -> Test<&'a str> {
    let prefix = format!("\"{name}\":\"");
    text.split_once(&prefix).and_then(|(_, tail)| tail.split_once('"')).map(|(value, _)| value)
        .ok_or_else(|| "required report string missing".into())
}

/// Serializes this binary's tests. Every test holds native flock owner locks in this process and
/// spawns real CLI processes. A child spawned by a concurrent test thread inherits, until its exec
/// closes it, every descriptor open at that instant, including another test's held owner lock; the
/// flock then outlives its owner's drop, and that test's next open or child sees Locked/Busy.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
#[test]
fn checking_old_recipe_reports_selected_and_observed_sources_without_publishing() -> Test {
    let _serial = serial();
    let f = seed("cli-historical-check", 2, false, false)?;
    let baseline = success(run(args(&f, false)?)?)?;
    let (head, roots) = {
        let mut p = open(&f.path)?; let head = append_tail(&mut p)?;
        (head, p.visible_roots().count())
    };
    let checked = success(run(args(&f, false)?)?)?;
    assert_eq!(field(&checked, "result_root")?, field(&baseline, "result_root")?);
    assert_eq!(field(&checked, "source_head")?, f.pin.source.head.to_text());
    assert_eq!(field(&checked, "observed_source_head_at_load")?, head.head.to_text());
    assert!(checked.contains(&format!("\"source_datagrams\":{}", f.pin.source.datagrams)));
    assert!(checked.contains(&format!("\"observed_source_datagrams_at_load\":{}", head.datagrams)));
    assert!(checked.contains("\"rtcp_observations\":0"));
    assert!(checked.contains("\"result_status\":\"not_requested\""));
    assert_eq!(open(&f.path)?.visible_roots().count(), roots);
    Ok(())
}

#[test]
fn lost_stdout_followed_by_capture_growth_and_new_process_retry_reuses_all_outputs() -> Test {
    let _serial = serial();
    let f = seed("cli-historical-retry", 2, false, false)?;
    let first = success(run(args(&f, true)?)?)?;
    let root = field(&first, "result_root")?.to_owned(); drop(first);
    let (head, roots) = {
        let mut p = open(&f.path)?; let head = append_tail(&mut p)?;
        (head, p.visible_roots().count())
    };
    let retried = success(run(args(&f, true)?)?)?;
    assert_eq!(field(&retried, "result_root")?, root);
    assert!(retried.contains("\"result_status\":\"already_durable\""));
    assert!(retried.contains("\"new_windows\":0"));
    assert!(retried.contains(&format!("\"reused_windows\":{}", f.expected.len())));
    let p = open(&f.path)?; assert_eq!(p.visible_roots().count(), roots);
    assert_eq!(current(&p)?.pin(), head);
    Ok(())
}

#[test]
fn namespace_limits_admit_full_chain_ceiling_but_never_ignore_real_limit_exhaustion() -> Test {
    let _serial = serial();
    let f = seed("cli-historical-bounds", 1, false, false)?;
    { let mut p = open(&f.path)?; append_tail(&mut p)?; }
    let mut expanded = args(&f, false)?;
    expanded.extend(["--max-datagrams".into(), "65536".into()]);
    success(run(expanded)?)?;
    let mut too_small = args(&f, true)?;
    too_small.extend(["--max-datagrams".into(), f.pin.source.datagrams.to_string().into()]);
    let denied = run(too_small)?;
    assert!(!denied.status.success()); assert!(denied.stdout.is_empty());
    let mut excessive = args(&f, false)?;
    excessive.extend(["--max-datagrams".into(), "65537".into()]);
    let denied = run(excessive)?;
    assert_eq!(denied.status.code(), Some(i32::from(ExitIdentity::MALFORMED_VALUE.code)));
    assert!(denied.stdout.is_empty());
    Ok(())
}
