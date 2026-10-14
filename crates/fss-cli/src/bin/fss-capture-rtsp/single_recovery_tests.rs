#![forbid(unsafe_code)]
//! Recovery requests preserve the original capture scope and never delegate to intake.

use super::*;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn args() -> Vec<OsString> {
    let mut input: Vec<OsString> = [
        ("--root", "/owner/archive"),
        ("--pins", "/owner/pins"),
        ("--peer", "127.0.0.1:8554"),
        ("--authority", "camera.test:8554"),
        ("--presentation", "/camera/main"),
        ("--control-root", "/camera"),
        ("--sensor-id", "sensor:camera"),
        ("--stream-id", "stream:main"),
        ("--generation", "1"),
        ("--ingress", "1"),
        ("--ssrc", "7"),
        ("--frame-duration-ticks", "18000"),
        ("--stop-after-pictures", "2"),
        ("--owner-authorized", "yes"),
        ("--plaintext", "yes"),
        ("--retain-originals", "yes"),
    ]
    .into_iter()
    .flat_map(|(key, value)| [OsString::from(key), OsString::from(value)])
    .collect();
    for key in ["--anchor", "--receive-clock", "--timing-evidence", "--journal-id"] {
        input.extend([
            key.into(),
            ContentDigest::sha256(key.as_bytes()).to_text().into(),
        ]);
    }
    input
}

fn set(input: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = input.iter().position(|arg| arg == key) {
        input[index + 1] = value.into();
    } else {
        input.extend([key.into(), value.into()]);
    }
}

#[test]
fn work_recovery_preserves_original_scope_including_optional_supervision() -> Test {
    for codec in ["avc", "hevc"] {
        for supervision in [None, Some("1"), Some("600000")] {
            let mut input = args();
            set(&mut input, "--codec", codec);
            if let Some(timeout) = supervision {
                set(&mut input, "--progress-timeout-ms", timeout);
            }
            let original = SinglePlan::parse(&input)?;
            set(&mut input, "--recover", "yes");
            let recovering = SinglePlan::parse(&input)?;
            assert_eq!(recovering.capture_digest()?, original.digest()?);
            assert_eq!(recovering.capture.digest()?, original.capture.digest()?);
            assert_eq!(recovering.attempts().len(), 1);
            assert!(std::ptr::eq(&recovering.attempts()[0], &recovering.capture));
            assert_eq!(recovering.capture.root, original.capture.root);
            assert_eq!(recovering.capture.pins, original.capture.pins);
            assert_eq!(
                recovering.capture.recording_config().scope.generation,
                original.capture.recording_config().scope.generation
            );
            assert_eq!(
                recovering.capture.recording_config().scope.receive_clock,
                original.capture.recording_config().scope.receive_clock
            );
            assert_eq!(
                recovering.capture.pin_scope().journal_id,
                original.capture.pin_scope().journal_id
            );
            assert_eq!(
                recovering.maximum_storage_bytes(),
                original.capture.publication_limits().spool.max_total_bytes
            );
            assert_eq!(recovering.recovery_timeout_ns, Some(30_000_000_000));
            assert!(!recovering.index_catalogs());
        }
    }
    Ok(())
}

#[test]
fn even_the_correct_capture_approval_cannot_admit_recovery_as_network_work() -> Test {
    let mut input = args();
    set(&mut input, "--progress-timeout-ms", "5000");
    let capture_approval = SinglePlan::parse(&input)?.digest()?;
    set(&mut input, "--approve", &capture_approval.to_text());
    set(&mut input, "--recover", "yes");
    let mut recovering = SinglePlan::parse(&input)?;
    let child_before = recovering.capture.approve;
    assert!(recovering.approved());
    assert_eq!(recovering.recovery_approval(), Some(capture_approval));
    assert_eq!(recovering.admit(), Err("ERR-CAPTURE-RTSP-STATE-001"));
    assert_eq!(recovering.capture.approve, child_before);
    Ok(())
}

#[test]
fn recovery_timeout_is_separate_from_the_capture_basis_and_never_widens_native_limits() -> Test {
    let mut input = args();
    let original = SinglePlan::parse(&input)?;
    set(&mut input, "--recover", "yes");
    for (milliseconds, nanoseconds) in [("1", 1_000_000), ("3600000", 3_600_000_000_000)] {
        set(&mut input, "--recovery-timeout-ms", milliseconds);
        let recovering = SinglePlan::parse(&input)?;
        assert_eq!(recovering.recovery_timeout_ns, Some(nanoseconds));
        assert_eq!(recovering.capture_digest()?, original.digest()?);
        assert_eq!(recovering.capture.timeout_ns, original.capture.timeout_ns);
        assert_eq!(recovering.capture.drain_timeout_ns, original.capture.drain_timeout_ns);
        assert_eq!(recovering.capture.max_steps, original.capture.max_steps);
    }
    Ok(())
}

#[test]
fn recovery_parser_refuses_ambiguous_malformed_or_unpaired_options() {
    let mut input = args();
    set(&mut input, "--recovery-timeout-ms", "30000");
    assert!(SinglePlan::parse(&input).is_err());
    set(&mut input, "--recover", "yes");
    for value in ["", "0", "3600001", "-1", "+1", "1.0", "1e3", "18446744073709551616"] {
        set(&mut input, "--recovery-timeout-ms", value);
        assert!(SinglePlan::parse(&input).is_err(), "{value}");
    }
    set(&mut input, "--recovery-timeout-ms", "30000");
    for value in ["no", "true", "YES", "repair"] {
        set(&mut input, "--recover", value);
        assert!(SinglePlan::parse(&input).is_err(), "{value}");
    }
    set(&mut input, "--recover", "yes");
    for (key, value) in [
        ("--recover", "yes"),
        ("--recovery-timeout-ms", "30000"),
        ("--max-attempts", "1"),
        ("--unknown", "yes"),
    ] {
        let mut invalid = input.clone();
        invalid.extend([key.into(), value.into()]);
        assert!(SinglePlan::parse(&invalid).is_err(), "{key}");
    }
    input.push("--recover".into());
    assert!(SinglePlan::parse(&input).is_err());
}

#[test]
fn recovery_does_not_increment_a_maximal_generation_or_rehash_receive_clocks() -> Test {
    let mut input = args();
    set(&mut input, "--generation", &u64::MAX.to_string());
    set(&mut input, "--ingress", &u128::MAX.to_string());
    let native = Options::parse(&input)?;
    set(&mut input, "--recover", "yes");
    let forward = SinglePlan::parse(&input)?;
    let reversed: Vec<_> = input
        .chunks_exact(2)
        .rev()
        .flat_map(|pair| pair.iter().cloned())
        .collect();
    let backward = SinglePlan::parse(&reversed)?;
    assert_eq!(forward.capture_digest()?, native.digest()?);
    assert_eq!(backward.capture_digest()?, forward.capture_digest()?);
    assert_eq!(forward.capture.recording_config().scope.generation, u64::MAX);
    assert_eq!(forward.capture.root, native.root);
    assert_eq!(forward.capture.pins, native.pins);
    Ok(())
}

#[test]
fn omitting_recovery_preserves_native_preview_and_capture_delegation() -> Test {
    for codec in ["avc", "hevc"] {
        let mut input = args();
        set(&mut input, "--codec", codec);
        let native = Options::parse(&input)?;
        let mut current = SinglePlan::parse(&input)?;
        assert_eq!(current.preview()?, native.preview()?);
        assert_eq!(current.recovery_timeout_ns, None);
        current.approval = Some(current.digest()?);
        assert_eq!(current.admit()?, None);
        assert_eq!(current.capture.approve, current.approval);
    }
    Ok(())
}
