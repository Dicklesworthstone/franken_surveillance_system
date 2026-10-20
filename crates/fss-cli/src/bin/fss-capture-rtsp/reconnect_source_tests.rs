#![forbid(unsafe_code)]
//! Source custody never silently degrades to recording-only capture or unpriced retries.
use super::*;
use std::collections::VecDeque;

type Test = Result<(), &'static str>;
const STORAGE: &str = "ERR-CAPTURE-RTSP-STORAGE-001";
const STATE: &str = "ERR-CAPTURE-RTSP-STATE-001";

fn args(codec: &str) -> Vec<OsString> {
    let mut values: Vec<OsString> = [
        ("--root", "/owner/archive"),
        ("--pins", "/owner/pins"),
        ("--peer", "127.0.0.1:8554"),
        ("--authority", "camera.test:8554"),
        ("--presentation", "/live/"),
        ("--control-root", "/live"),
        ("--sensor-id", "sensor:camera"),
        ("--stream-id", "stream:main"),
        ("--generation", "7"),
        ("--ingress", "71"),
        ("--ssrc", "7"),
        ("--frame-duration-ticks", "3600"),
        ("--stop-after-pictures", "2"),
        ("--owner-authorized", "yes"),
        ("--plaintext", "yes"),
        ("--retain-originals", "yes"),
        ("--codec", codec),
        ("--max-attempts", "2"),
        ("--retry-delay-ms", "1"),
        ("--payload-type", if codec == "avc" { "96" } else { "98" }),
    ]
    .into_iter()
    .flat_map(|(key, value)| [key.into(), value.into()])
    .collect();
    for (key, label) in [
        ("--anchor", "anchor"),
        ("--receive-clock", "receive"),
        ("--timing-evidence", "timing"),
        ("--journal-id", "pins"),
    ] {
        values.extend([
            key.into(),
            ContentDigest::sha256(label.as_bytes()).to_text().into(),
        ]);
    }
    values
}
fn set(values: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(at) = values.iter().position(|v| v == key) {
        values[at + 1] = value.into();
    } else {
        values.extend([key.into(), value.into()]);
    }
}
fn retained_args(codec: &str) -> Vec<OsString> {
    let mut values = args(codec);
    set(&mut values, "--source-root", "/owner/source");
    set(
        &mut values,
        "--source-retention-evidence",
        &ContentDigest::sha256(b"retain RTP and RTCP").to_text(),
    );
    set(&mut values, "--max-datagrams", "32");
    set(&mut values, "--source-storage-bytes", "1048576");
    set(&mut values, "--source-work", "1000000");
    values
}
fn approve(plan: &mut ReconnectPlan) -> Test {
    plan.approve = Some(plan.digest()?);
    for index in 0..plan.attempts.len() {
        plan.attempts[index].approve = Some(plan.child_approval(index)?);
    }
    Ok(())
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
    results: VecDeque<AttemptOutcome>,
    sources: Vec<(u64, std::path::PathBuf, ContentDigest, u64)>,
    ordinary: usize,
    waits: usize,
    rows: Vec<(String, String)>,
}
impl Effects for Script {
    fn checkpoint(&mut self) -> Test {
        Ok(())
    }
    fn emit(&mut self, kind: &str, detail: String) -> Test {
        self.rows.push((kind.into(), detail));
        Ok(())
    }
    fn capture(&mut self, _: &Options) -> Result<AttemptOutcome, &'static str> {
        self.ordinary += 1;
        Err("source retention silently omitted")
    }
    fn capture_retained(
        &mut self,
        options: &Options,
        source: &SourceConfig,
    ) -> Result<AttemptOutcome, &'static str> {
        assert_eq!(options.approve, Some(source.digest(options)?));
        assert_ne!(options.approve, Some(options.digest()?));
        assert_eq!(source.scope.binding, options.binding());
        assert_eq!(
            source.scope.receive_clock,
            options.recording_config().scope.receive_clock
        );
        self.sources.push((
            source.scope.binding.key().generation,
            source.root.clone(),
            source.scope.receive_clock,
            source.work,
        ));
        self.results.pop_front().ok_or("unexpected successor")
    }
    fn pause(&mut self, _: u64) -> Test {
        self.waits += 1;
        Ok(())
    }
}

#[test]
fn source_reconnect_is_opt_in_and_preserves_ordinary_child_approvals() -> Test {
    for codec in ["avc", "hevc"] {
        let original = ReconnectPlan::parse(&args(codec))?;
        let enabled = ReconnectPlan::parse(&retained_args(codec))?;
        assert!(original.sources.is_none());
        assert!(!original.preview()?.contains("datagram_source_custody"));
        assert_ne!(original.digest()?, enabled.digest()?);
        assert_eq!(original.maximum_capture_ns, enabled.maximum_capture_ns);
        assert_eq!(original.maximum_source_bytes, enabled.maximum_source_bytes);
        assert_eq!(
            original.maximum_storage_bytes,
            enabled.maximum_storage_bytes
        );
        assert_eq!(original.maximum_report_bytes, enabled.maximum_report_bytes);
        for (old, new) in original.attempts.iter().zip(&enabled.attempts) {
            assert_eq!(old.digest()?, new.digest()?);
        }
        assert!(
            enabled
                .preview()?
                .contains("\"maximum_datagrams_all_attempts\":64")
        );
        assert!(
            enabled
                .preview()?
                .contains("\"maximum_source_spool_bytes_all_attempts\":2097152")
        );
        assert!(
            enabled
                .preview()?
                .contains("\"maximum_source_work_all_attempts\":2000000")
        );
    }
    Ok(())
}

#[test]
fn every_source_input_changes_outer_approval_and_each_child_retention_grant() -> Test {
    let input = retained_args("avc");
    let initial = ReconnectPlan::parse(&input)?;
    for (key, value) in [
        ("--source-root", "/owner/other-source"),
        (
            "--source-retention-evidence",
            &ContentDigest::sha256(b"different policy").to_text(),
        ),
        ("--max-datagrams", "33"),
        ("--source-storage-bytes", "2097152"),
        ("--source-work", "1000001"),
    ] {
        let mut changed = input.clone();
        set(&mut changed, key, value);
        let changed = ReconnectPlan::parse(&changed)?;
        assert_ne!(initial.digest()?, changed.digest()?);
        for index in 0..2 {
            assert_ne!(
                initial.child_approval(index)?,
                changed.child_approval(index)?
            );
            assert_eq!(
                initial.attempts[index].digest()?,
                changed.attempts[index].digest()?
            );
        }
    }
    Ok(())
}

#[test]
fn partial_source_grants_invalid_paths_and_duplicate_options_refuse_purely() -> Test {
    for (key, value) in [
        ("--max-datagrams", "32"),
        ("--source-root", "/owner/source"),
        ("--source-work", "100"),
        ("--source-storage-bytes", "1048576"),
    ] {
        let mut input = args("avc");
        set(&mut input, key, value);
        assert!(ReconnectPlan::parse(&input).is_err());
    }
    for (key, value) in [
        ("--source-root", "/owner/archive"),
        ("--source-root", "/owner/pins/sub"),
        ("--source-root", "relative"),
        ("--source-root", "/owner/../source"),
        ("--source-root", "/"),
        ("--max-datagrams", "65537"),
        ("--max-datagrams", "0"),
        ("--source-work", "0"),
        ("--source-storage-bytes", "1"),
    ] {
        let mut input = retained_args("avc");
        set(&mut input, key, value);
        assert!(ReconnectPlan::parse(&input).is_err(), "{key}={value}");
    }
    let mut input = retained_args("avc");
    input.extend(["--source-work".into(), "10".into()]);
    assert!(ReconnectPlan::parse(&input).is_err());
    Ok(())
}

#[test]
fn source_epochs_are_independent_and_aggregate_limits_cover_all_sixteen_attempts() -> Test {
    let mut input = retained_args("hevc");
    set(&mut input, "--max-attempts", "16");
    let plan = ReconnectPlan::parse(&input)?;
    let sources = plan.sources.as_ref().ok_or(STATE)?;
    for index in 0..16 {
        let source = sources.get(index)?;
        assert_eq!(source.scope.binding.key().generation, 7 + index as u64);
        assert_eq!(
            source.root,
            std::path::PathBuf::from(format!("/owner/source.attempt-{:04}", index + 1))
        );
        assert_eq!(source.scope.binding, plan.attempts[index].binding());
        assert_eq!(
            source.scope.receive_clock,
            plan.attempts[index].recording_config().scope.receive_clock
        );
        assert_eq!(source.work, 1_000_000);
        for earlier in 0..index {
            assert_ne!(
                source.scope.digest().map_err(|_| STATE)?,
                sources.get(earlier)?.scope.digest().map_err(|_| STATE)?
            );
            assert_ne!(
                source.scope.receive_clock,
                sources.get(earlier)?.scope.receive_clock
            );
        }
    }
    let preview = plan.preview()?;
    assert!(preview.contains("\"maximum_datagrams_all_attempts\":512"));
    assert!(preview.contains("\"maximum_source_spool_bytes_all_attempts\":16777216"));
    assert!(preview.contains("\"maximum_source_work_all_attempts\":16000000"));
    Ok(())
}

#[test]
fn ordinary_or_retained_child_approval_cannot_start_a_source_campaign() -> Test {
    let mut plan = ReconnectPlan::parse(&retained_args("avc"))?;
    let legacy = ReconnectPlan::parse(&args("avc"))?;
    for stale in [
        legacy.digest()?,
        plan.attempts[0].digest()?,
        plan.child_approval(0)?,
    ] {
        plan.approve = Some(stale);
        let mut script = Script::default();
        assert_eq!(
            run(&plan, &mut script),
            Err("ERR-CAPTURE-RTSP-APPROVAL-001")
        );
        assert!(script.rows.is_empty());
        assert!(script.sources.is_empty());
        assert_eq!(script.ordinary, 0);
        assert_eq!(script.waits, 0);
    }
    Ok(())
}

#[test]
fn timed_campaign_delegates_each_source_plan_through_the_same_native_controller() -> Test {
    for codec in ["avc", "hevc"] {
        let mut input = retained_args(codec);
        set(&mut input, "--capture-duration-ms", "1000");
        set(&mut input, "--progress-timeout-ms", "500");
        set(&mut input, "--continue-after-success", "yes");
        let mut plan = ReconnectPlan::parse(&input)?;
        approve(&mut plan)?;
        assert!(plan.supervision(plan.digest()?)?.is_some());
        let mut script = Script {
            results: [success(), success()].into(),
            ..Script::default()
        };
        assert_eq!(run(&plan, &mut script), Ok(()));
        assert_eq!(script.sources.len(), 2);
        assert_eq!(script.ordinary, 0);
        assert_eq!(script.waits, 1);
        assert_ne!(script.sources[0].1, script.sources[1].1);
        assert_ne!(script.sources[0].2, script.sources[1].2);
        for (_, _, _, work) in &script.sources {
            assert_eq!(*work, 1_000_000);
        }
    }
    Ok(())
}

#[test]
fn source_failure_or_uncertainty_stops_even_when_the_recording_is_fully_durable() -> Test {
    let mut plan = ReconnectPlan::parse(&retained_args("avc"))?;
    approve(&mut plan)?;
    for (result, retry, recovery_required) in [
        (Err(STORAGE), None, false),
        (Err(STORAGE), Some(driver::RetryReason::SourceEnded), true),
        (Ok(()), Some(driver::RetryReason::SettledSuccess), true),
    ] {
        let outcome = AttemptOutcome {
            result,
            retry,
            recovery_required,
            durable_pictures: 2,
        };
        let mut script = Script {
            results: [outcome, success()].into(),
            ..Script::default()
        };
        assert_eq!(
            run(&plan, &mut script),
            if result.is_ok() { Err(STATE) } else { result }
        );
        assert_eq!(script.sources.len(), 1);
        assert_eq!(script.waits, 0);
    }
    Ok(())
}

#[test]
fn a_controller_without_source_support_cannot_fall_back_to_ordinary_capture() -> Test {
    struct RecordingOnly;
    impl Effects for RecordingOnly {
        fn checkpoint(&mut self) -> Test {
            Ok(())
        }
        fn emit(&mut self, _: &str, _: String) -> Test {
            Ok(())
        }
        fn capture(&mut self, _: &Options) -> Result<AttemptOutcome, &'static str> {
            Err("ordinary capture must not run")
        }
        fn pause(&mut self, _: u64) -> Test {
            Err("backoff must not run")
        }
    }
    let mut plan = ReconnectPlan::parse(&retained_args("avc"))?;
    approve(&mut plan)?;
    assert_eq!(run(&plan, &mut RecordingOnly), Err(STATE));
    Ok(())
}

#[test]
fn recovery_preserves_all_original_source_scopes_and_capture_identity() -> Test {
    for mode in ["yes", "index"] {
        let mut input = retained_args("avc");
        let capture = ReconnectPlan::parse(&input)?;
        set(&mut input, "--recover", mode);
        let recovery = ReconnectPlan::parse(&input)?;
        assert_eq!(capture.digest()?, recovery.digest()?);
        for index in 0..capture.attempts.len() {
            assert_eq!(
                capture.child_approval(index)?,
                recovery.child_approval(index)?
            );
            let before = capture.sources.as_ref().ok_or(STATE)?.get(index)?;
            let after = recovery.sources.as_ref().ok_or(STATE)?.get(index)?;
            assert_eq!(before.root, after.root);
            assert_eq!(before.scope, after.scope);
        }
    }
    Ok(())
}
