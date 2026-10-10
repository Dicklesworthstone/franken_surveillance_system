#![forbid(unsafe_code)]
//! Pure admission tests: invalid replay requests never reach deployment I/O.

use super::*;

fn args(action: &str) -> Vec<OsString> {
    vec![
        action.into(),
        "--root".into(),
        "/nonexistent/fss-replay-unit".into(),
        "--site".into(),
        "site:replay-cli-unit".into(),
        "--event-id".into(),
        format!("event:long-watch:{}", "1".repeat(64)).into(),
    ]
}
fn verify() -> Vec<OsString> {
    let mut args = args("verify");
    args.extend([
        "--expected-event-revision".into(),
        ContentDigest::sha256(b"revision").to_text().into(),
        "--expected-provenance-root".into(),
        ContentDigest::sha256(b"provenance").to_text().into(),
        "--execute-perception".into(),
        "yes".into(),
    ]);
    args
}

#[test]
fn only_whole_recording_reads_and_explicit_verify_take_this_dispatch() {
    assert!(handles(&args("read")));
    assert!(handles(&verify()));
    let mut ordinary = args("read");
    ordinary[6] = format!("event:recorded:{}", "1".repeat(64)).into();
    assert!(!handles(&ordinary));
    ordinary[6] = format!("event:package:{}", "1".repeat(64)).into();
    assert!(!handles(&ordinary));
    ordinary[6] = format!("event:long-dwell:{}", "1".repeat(64)).into();
    assert!(!handles(&ordinary));
    ordinary[6] = format!("event:long-corroborated:{}", "1".repeat(64)).into();
    assert!(handles(&ordinary));
    assert!(!handles(&args("publish")));
}

#[test]
fn verify_needs_both_nonzero_pins_and_explicit_execution() {
    assert!(parse(&verify()).is_ok());
    assert!(parse(&args("verify")).is_err());
    for remove in ["--expected-event-revision", "--expected-provenance-root", "--execute-perception"] {
        let mut request = verify();
        let index = request.iter().position(|value| value == remove).unwrap();
        request.drain(index..index + 2);
        assert!(parse(&request).is_err(), "{remove}");
    }
    let mut request = verify();
    *request.last_mut().unwrap() = "no".into();
    assert!(parse(&request).is_err());
    let mut request = verify();
    let index = request.iter().position(|value| value == "--expected-event-revision").unwrap();
    request[index + 1] = format!("sha256:{}", "0".repeat(64)).into();
    assert!(parse(&request).is_err());
    let mut request = verify();
    request[6] = "event:recorded:outside-profile".into();
    assert!(parse(&request).is_err());
}

#[test]
fn read_rejects_execution_and_both_modes_reject_interpretation_or_publication_overrides() {
    let mut request = args("read");
    request.extend(["--execute-perception".into(), "yes".into()]);
    assert!(parse(&request).is_err());
    for flag in [
        "--approve", "--proposal-digest", "--report", "--report-digest", "--import-id",
        "--interpretation", "--zone", "--camera", "--ground", "--sensor-health",
        "--detector-package", "--pixel-threshold", "--expected-analysis-root",
    ] {
        let mut request = verify();
        request.extend([flag.into(), "untrusted".into()]);
        assert!(parse(&request).is_err(), "{flag}");
    }
}

#[test]
fn duplicate_options_and_partial_pairs_are_rejected() {
    let mut request = args("read");
    request.extend(["--site".into(), "site:another".into()]);
    assert!(parse(&request).is_err());
    let mut request = verify();
    request.push("--max-report-bytes".into());
    assert!(parse(&request).is_err());
    let mut request = args("read");
    request.extend(["--principal".into(), "--max-pixels".into()]);
    assert!(parse(&request).is_err());
    let mut request = args("read");
    request[2] = "relative-root".into();
    assert!(parse(&request).is_err());
}

#[test]
fn every_exposed_budget_is_positive_bounded_unsigned_decimal() {
    for flag in [
        "--max-metadata-bytes", "--max-report-bytes", "--source-read-bytes", "--pixel-budget",
        "--assignment-work", "--trace-bytes", "--decode-work", "--max-dimension",
        "--max-pixels", "--max-segment-bytes",
    ] {
        for value in ["0", "-1", "+1", "18446744073709551616", "1.5"] {
            let mut request = args("read");
            request.extend([flag.into(), value.into()]);
            assert!(parse(&request).is_err(), "{flag} {value}");
        }
    }
    let mut request = args("read");
    request.extend(["--max-report-bytes".into(), "16777217".into()]);
    assert!(parse(&request).is_err());
    let mut request = args("read");
    request.extend(["--max-metadata-bytes".into(), "268435457".into()]);
    assert!(parse(&request).is_err());
    let mut request = args("read");
    request.extend(["--max-metadata-bytes".into(), "268435456".into()]);
    assert!(parse(&request).is_ok());
    let mut request = args("read");
    request.extend(["--max-dimension".into(), "15".into()]);
    assert!(parse(&request).is_err());
}

#[cfg(unix)]
#[test]
fn root_and_export_paths_preserve_os_bytes_without_lossy_conversion() {
    use std::os::unix::ffi::OsStringExt;
    let root = OsString::from_vec(b"/fss-root-\xff".to_vec());
    let event = OsString::from_vec(b"/fss-output-\xfe".to_vec());
    let mut request = args("read");
    request[2] = root.clone();
    request.extend(["--event-out".into(), event.clone()]);
    let parsed = parse(&request).unwrap();
    assert_eq!(parsed.root.as_os_str(), root.as_os_str());
    assert_eq!(parsed.event_out.unwrap().as_os_str(), event.as_os_str());
}

#[test]
fn output_interruptions_have_a_finite_retry_budget() {
    struct InterruptedOutput {
        remaining: usize,
        bytes: Vec<u8>,
    }
    impl Write for InterruptedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.remaining > 0 {
                self.remaining -= 1;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut recoverable = InterruptedOutput { remaining: 8, bytes: Vec::new() };
    emit(&mut recoverable, b"complete output").unwrap();
    assert_eq!(recoverable.bytes, b"complete output");
    let mut repeated = InterruptedOutput { remaining: 9, bytes: Vec::new() };
    assert_eq!(emit(&mut repeated, b"no output").unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert!(repeated.bytes.is_empty());
}

#[test]
fn long_event_identity_requires_its_exact_canonical_suffix_before_io() {
    for suffix in [
        "malformed".to_owned(),
        "A".repeat(64),
        "g".repeat(64),
        "1".repeat(63),
        format!("extra:{}", "1".repeat(64)),
    ] {
        let mut request = args("read");
        request[6] = format!("event:long-watch:{suffix}").into();
        assert!(handles(&request));
        assert!(parse(&request).is_err(), "{suffix}");
    }
}
