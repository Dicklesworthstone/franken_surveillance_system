#![forbid(unsafe_code)]
//! Deterministic controller tests; native source verification remains in the capture owners.

use super::*;
use std::collections::VecDeque;

const SOURCE: &str = "ERR-CAPTURE-RTSP-SOURCE-001";
const AUTHORITY: &str = "ERR-CAPTURE-RTSP-AUTHORITY-001";
const OUTPUT: &str = "ERR-CAPTURE-RTSP-OUTPUT-001";

type TestResult = Result<(), &'static str>;

fn arguments_for(codec: &str, count: usize) -> Vec<OsString> {
    let mut args: Vec<OsString> = [
        ("--root", "/owner/private/archive"),
        ("--pins", "/owner/private/pins"),
        ("--peer", "127.0.0.1:8554"),
        ("--authority", "camera.test:8554"),
        ("--presentation", "/camera/main"),
        ("--control-root", "/camera"),
        ("--sensor-id", "sensor:camera"),
        ("--stream-id", "stream:main"),
        ("--generation", "1"),
        ("--ingress", "1"),
        ("--ssrc", "7"),
        ("--frame-duration-ticks", "3600"),
        ("--stop-after-pictures", "2"),
        ("--retry-delay-ms", "1"),
        ("--retry-max-delay-ms", "4"),
        ("--owner-authorized", "yes"),
        ("--plaintext", "yes"),
        ("--retain-originals", "yes"),
        ("--codec", codec),
        ("--payload-type", if codec == "hevc" { "98" } else { "96" }),
    ]
    .into_iter()
    .flat_map(|(key, value)| [OsString::from(key), OsString::from(value)])
    .collect();
    args.extend(["--max-attempts".into(), count.to_string().into()]);
    for (key, digit) in [
        ("--anchor", "1"),
        ("--receive-clock", "2"),
        ("--timing-evidence", "3"),
        ("--journal-id", "4"),
    ] {
        args.extend([key.into(), format!("sha256:{}", digit.repeat(64)).into()]);
    }
    args
}

fn plan(
    codec: &str,
    count: usize,
    interrupted: bool,
    campaign: bool,
) -> Result<ReconnectPlan, &'static str> {
    let mut args = arguments_for(codec, count);
    if interrupted {
        args.extend(["--retry-interrupted".into(), "yes".into()]);
    }
    if campaign {
        args.extend(["--continue-after-success".into(), "yes".into()]);
    }
    let mut plan = ReconnectPlan::parse(&args)?;
    plan.approve = Some(plan.digest()?);
    for child in &mut plan.attempts {
        child.approve = Some(child.digest()?);
    }
    Ok(plan)
}

fn interrupted() -> AttemptOutcome {
    AttemptOutcome {
        result: Err(SOURCE),
        retry: Some(driver::RetryReason::ReadInterrupted),
        recovery_required: false,
        durable_pictures: 1,
    }
}

fn success() -> AttemptOutcome {
    AttemptOutcome {
        result: Ok(()),
        retry: Some(driver::RetryReason::SettledSuccess),
        recovery_required: false,
        durable_pictures: 2,
    }
}

#[derive(Default)]
struct Script {
    outcomes: VecDeque<AttemptOutcome>,
    generations: Vec<u64>,
    receives: Vec<ContentDigest>,
    journals: Vec<ContentDigest>,
    roots: Vec<std::path::PathBuf>,
    rows: Vec<(String, String)>,
    waits: Vec<u64>,
    fail_emit: Option<&'static str>,
    cancel_in_pause: bool,
    cancelled: bool,
}
impl Script {
    fn new(outcomes: impl IntoIterator<Item = AttemptOutcome>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
            ..Self::default()
        }
    }
    fn rows(&self, kind: &str) -> Vec<&str> {
        self.rows
            .iter()
            .filter(|(name, _)| name == kind)
            .map(|(_, row)| row.as_str())
            .collect()
    }
}
impl Effects for Script {
    fn checkpoint(&mut self) -> TestResult {
        if self.cancelled {
            Err(AUTHORITY)
        } else {
            Ok(())
        }
    }
    fn emit(&mut self, kind: &str, detail: String) -> TestResult {
        if self.fail_emit == Some(kind) {
            return Err(OUTPUT);
        }
        self.rows.push((kind.into(), detail));
        Ok(())
    }
    fn capture(&mut self, options: &Options) -> Result<AttemptOutcome, &'static str> {
        assert_eq!(options.approve, Some(options.digest()?));
        let scope = options.recording_config().scope;
        self.generations.push(scope.generation);
        self.receives.push(scope.receive_clock);
        self.journals.push(options.pin_scope().journal_id);
        self.roots.push(options.root.clone());
        self.outcomes.pop_front().ok_or("unapproved extra capture")
    }
    fn pause(&mut self, milliseconds: u64) -> TestResult {
        self.waits.push(milliseconds);
        self.cancelled |= self.cancel_in_pause;
        Ok(())
    }
}

#[test]
fn interruption_retry_requires_new_outer_approval_without_widening_any_child() -> TestResult {
    for codec in ["avc", "hevc"] {
        let legacy = plan(codec, 2, false, false)?;
        let mut enabled = plan(codec, 2, true, false)?;
        assert!(!legacy.retry_interrupted);
        assert!(enabled.retry_interrupted);
        assert_ne!(legacy.digest()?, enabled.digest()?);
        assert_eq!(legacy.maximum_source_bytes, enabled.maximum_source_bytes);
        assert_eq!(legacy.maximum_storage_bytes, enabled.maximum_storage_bytes);
        assert_eq!(legacy.maximum_capture_ns, enabled.maximum_capture_ns);
        assert_eq!(legacy.maximum_report_bytes, enabled.maximum_report_bytes);
        assert_eq!(legacy.maximum_backoff_ms, enabled.maximum_backoff_ms);
        for (old, new) in legacy.attempts.iter().zip(&enabled.attempts) {
            assert_eq!(old.digest()?, new.digest()?);
        }
        assert!(!legacy.preview()?.contains("retry_interrupted"));
        let preview = enabled.preview()?;
        assert!(preview.contains("\"retry_interrupted\":true"));
        assert!(preview.contains(INTERRUPTION_POLICY));
        assert!(preview.contains("\"interrupted_attempt_is_success\":false"));
        for stale in [legacy.digest()?, enabled.attempts[0].digest()?] {
            enabled.approve = Some(stale);
            let mut script = Script::new([interrupted(), success()]);
            assert_eq!(
                run(&enabled, &mut script),
                Err("ERR-CAPTURE-RTSP-APPROVAL-001")
            );
            assert!(script.generations.is_empty());
            assert!(script.rows.is_empty());
            assert!(script.waits.is_empty());
        }
        enabled.retry_interrupted = false;
        assert_eq!(enabled.digest()?, legacy.digest()?);
        assert_eq!(enabled.preview()?, legacy.preview()?);
    }
    Ok(())
}

#[test]
fn interruption_option_is_explicit_duplicate_safe_and_not_ordinary_capture_authority() -> TestResult
{
    for value in ["no", "true", "1", "YES", "", "yes "] {
        let mut args = arguments_for("avc", 2);
        args.extend(["--retry-interrupted".into(), value.into()]);
        assert!(ReconnectPlan::parse(&args).is_err(), "{value}");
    }
    let mut args = arguments_for("avc", 2);
    args.extend(["--retry-interrupted".into(), "yes".into()]);
    assert!(ReconnectPlan::parse(&args).is_ok());
    args.extend(["--retry-interrupted".into(), "yes".into()]);
    assert!(ReconnectPlan::parse(&args).is_err());
    // The underlying Options parser must never absorb this outer permission.
    let mut ordinary = arguments_for("avc", 2);
    for key in ["--max-attempts", "--retry-delay-ms", "--retry-max-delay-ms"] {
        let at = ordinary
            .iter()
            .position(|value| value == key)
            .ok_or("missing outer option")?;
        ordinary.drain(at..at + 2);
    }
    assert!(Options::parse(&ordinary).is_ok());
    ordinary.extend(["--retry-interrupted".into(), "yes".into()]);
    assert!(Options::parse(&ordinary).is_err());
    Ok(())
}

#[test]
fn legacy_reconnect_and_progress_supervision_do_not_grant_interruption_retries() -> TestResult {
    for supervised in [false, true] {
        let mut args = arguments_for("avc", 2);
        if supervised {
            args.extend(["--progress-timeout-ms".into(), "5000".into()]);
        }
        let mut plan = ReconnectPlan::parse(&args)?;
        plan.approve = Some(plan.digest()?);
        for child in &mut plan.attempts {
            child.approve = Some(child.digest()?);
        }
        let mut script = Script::new([interrupted(), success()]);
        assert_eq!(run(&plan, &mut script), Err(SOURCE));
        assert_eq!(script.generations, [1]);
        assert!(script.waits.is_empty());
        assert!(script.rows("attempt_finished")[0].contains("\"retrying\":false"));
    }
    Ok(())
}

#[test]
fn verified_interruptions_can_reconnect_but_never_merge_generations_or_failures() -> TestResult {
    for codec in ["avc", "hevc"] {
        let mut script = Script::new([interrupted(), success()]);
        assert_eq!(run(&plan(codec, 3, true, false)?, &mut script), Ok(()));
        assert_eq!(script.generations, [1, 2]);
        assert_ne!(script.receives[0], script.receives[1]);
        assert_ne!(script.journals[0], script.journals[1]);
        assert_ne!(script.roots[0], script.roots[1]);
        assert_eq!(script.waits, [1]);
        let rows = script.rows("attempt_finished");
        assert_eq!(rows.len(), 2);
        assert!(rows[0].contains("\"complete\":false"));
        assert!(rows[0].contains(SOURCE));
        assert!(rows[0].contains("read_interrupted_after_verified_drain"));
        assert!(rows[0].contains("\"retrying\":true"));
        assert!(rows[1].contains("\"complete\":true"));
        assert!(rows[1].contains("\"durable_pictures_all_attempts\":3"));
        for row in rows {
            assert!(row.contains("\"continuity_across_attempts\":false"));
        }
    }
    Ok(())
}

#[test]
fn interrupted_campaign_keeps_failure_after_later_sessions_settle_successfully() -> TestResult {
    for codec in ["avc", "hevc"] {
        let mut script = Script::new([interrupted(), success(), success()]);
        assert_eq!(run(&plan(codec, 3, true, true)?, &mut script), Err(SOURCE));
        assert_eq!(script.generations, [1, 2, 3]);
        let terminal = script.rows("reconnect_terminal")[0];
        assert!(terminal.contains("\"complete\":false"));
        assert!(terminal.contains("\"successful_attempts\":2"));
        assert!(terminal.contains("\"first_failed_attempt\":1"));
        assert!(terminal.contains(SOURCE));
        assert!(terminal.contains("\"absence_certifiable\":false"));
    }
    Ok(())
}

#[test]
fn interruption_marker_cannot_mask_wrong_error_empty_prefix_overcapture_or_recovery() -> TestResult
{
    for condition in 0..7 {
        let mut outcome = interrupted();
        match condition {
            0 => outcome.result = Err("ERR-CAPTURE-RTSP-AUTH-REFUSED-001"),
            1 => outcome.result = Err("ERR-CAPTURE-RTSP-STORAGE-001"),
            2 => outcome.result = Err("ERR-CAPTURE-RTSP-TIMING-001"),
            3 => outcome.durable_pictures = 0,
            4 => outcome.durable_pictures = 3,
            5 => outcome.recovery_required = true,
            _ => outcome.retry = None,
        }
        let expected = outcome.result;
        let mut script = Script::new([outcome, success()]);
        assert_eq!(run(&plan("avc", 2, true, false)?, &mut script), expected);
        assert_eq!(script.generations, [1]);
        assert!(script.waits.is_empty());
        assert!(script.rows("attempt_finished")[0].contains("\"retrying\":false"));
    }
    Ok(())
}

#[test]
fn interruption_retry_exhausts_only_approved_attempts_and_capped_waits() -> TestResult {
    for count in [1, 2, 16] {
        let plan = plan("avc", count, true, false)?;
        let mut script = Script::new((0..count).map(|_| interrupted()));
        assert_eq!(run(&plan, &mut script), Err(SOURCE));
        assert_eq!(script.generations.len(), count);
        assert!(script.outcomes.is_empty());
        assert_eq!(script.waits.len(), count - 1);
        assert_eq!(script.waits.iter().sum::<u64>(), plan.maximum_backoff_ms);
        assert!(script.waits.iter().all(|delay| *delay <= 4));
        assert!(script.rows("reconnect_terminal")[0].contains("\"attempt_limit_reached\":true"));
    }
    Ok(())
}

#[test]
fn lost_output_and_backoff_revocation_stop_before_successor_capture() -> TestResult {
    for fail_emit in ["attempt_finished", "backoff"] {
        let mut script = Script::new([interrupted(), success()]);
        script.fail_emit = Some(fail_emit);
        assert_eq!(run(&plan("avc", 2, true, false)?, &mut script), Err(OUTPUT));
        assert_eq!(script.generations, [1]);
        assert!(script.waits.is_empty());
    }
    let mut script = Script::new([interrupted(), success()]);
    script.cancel_in_pause = true;
    assert_eq!(
        run(&plan("avc", 2, true, false)?, &mut script),
        Err(AUTHORITY)
    );
    assert_eq!(script.generations, [1]);
    assert_eq!(script.waits, [1]);
    Ok(())
}

#[test]
fn recovery_keeps_original_interruption_identity_and_cannot_enter_capture_controller() -> TestResult
{
    for mode in ["yes", "index"] {
        let enabled = plan("avc", 2, true, false)?;
        let mut args = arguments_for("avc", 2);
        args.extend([
            "--retry-interrupted".into(),
            "yes".into(),
            "--recover".into(),
            mode.into(),
        ]);
        let recovered = ReconnectPlan::parse(&args)?;
        assert!(recovered.retry_interrupted);
        assert_eq!(enabled.digest()?, recovered.digest()?);
        let mut script = Script::default();
        assert_eq!(
            run(&recovered, &mut script),
            Err("ERR-CAPTURE-RTSP-STATE-001")
        );
        assert!(script.rows.is_empty());
        assert!(script.generations.is_empty());
    }
    Ok(())
}
