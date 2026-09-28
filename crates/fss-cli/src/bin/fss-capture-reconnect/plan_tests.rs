#![forbid(unsafe_code)]
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn arguments() -> Vec<OsString> {
    let d = ContentDigest::sha256(b"explicit reconnect test scope").to_text();
    ["--root", "/tmp/fss-reconnect-preview", "--peer", "127.0.0.1:8999", "--host", "camera.invalid",
        "--target", "/stream", "--source", &d, "--generations", "40,41,50", "--receive-clock", &d,
        "--retention-evidence", &d, "--owner-authorized", "yes", "--plaintext", "yes", "--retain-originals", "yes"]
        .into_iter().map(Into::into).collect()
}
fn replace(args: &mut [OsString], key: &str, value: &str) -> Result<(), &'static str> {
    let index = args.iter().position(|s| s == key).ok_or("missing option")?;
    args[index + 1] = value.into();
    Ok(())
}
#[test]
fn preview_reserves_all_slots_and_never_manufactures_a_generation() -> TestResult {
    let options = Options::parse(&arguments())?;
    assert_eq!(options.generations, [40, 41, 50]);
    let r = options.recording()?.reservation();
    assert_eq!(r.connections, 3);
    assert_eq!(r.wire_bytes, 3 * options.native.http.wire_bytes);
    assert_eq!(r.frames, 3 * (options.per_slot_frames + 1));
    assert_eq!(r.framing_work, options.policy.framing_work); // NOT multiplied or reset.
    assert!(options.preview().contains("\"generations\":[\"40\",\"41\",\"50\"]"));
    assert!(options.preview().contains("\"writes\":\"none\""));
    assert!(options.preview().contains("\"network\":\"none\""));
    Ok(())
}
#[test]
fn generation_errors_and_overflow_are_refused_without_sorting_or_wrapping() -> TestResult {
    for value in ["0", "1,1", "2,1", "1,", ",1", "1, 2", "+1", "-1", "18446744073709551616"] {
        let mut args = arguments(); replace(&mut args, "--generations", value)?;
        assert!(Options::parse(&args).is_err(), "accepted {value}");
    }
    let mut args = arguments();
    replace(&mut args, "--generations", "18446744073709551614,18446744073709551615")?;
    let options = Options::parse(&args)?;
    assert_eq!(options.generations.last(), Some(&u64::MAX));
    assert!(options.preview().contains("\"18446744073709551615\""));
    Ok(())
}
#[test]
fn exact_approval_binds_every_independent_option_and_is_not_its_own_input() -> TestResult {
    let args = arguments(); let original = Options::parse(&args)?.approval();
    for (key, value) in [("--root", "/tmp/other"), ("--peer", "127.0.0.1:8998"),
        ("--host", "other.invalid"), ("--target", "/other"), ("--generations", "40,42,50")] {
        let mut edited = args.clone(); replace(&mut edited, key, value)?;
        assert_ne!(original, Options::parse(&edited)?.approval(), "{key}");
    }
    for (key, value) in [("--principal", "principal:other"), ("--after-complete", "yes"),
        ("--max-source-work", "7"), ("--max-framing-work", "7"), ("--max-frames", "2"),
        ("--max-reads", "2"), ("--initial-backoff-ms", "251"), ("--maximum-backoff-ms", "5001"),
        ("--timeout-ms", "30001"), ("--max-steps", "33"), ("--max-io-calls", "33"),
        ("--max-report-bytes", "131072"), ("--stop-after-frames", "200")] {
        let mut edited = args.clone(); edited.extend([key.into(), value.into()]);
        assert_ne!(original, Options::parse(&edited)?.approval(), "{key}");
    }
    let mut approved = args; approved.extend(["--approve".into(), original.to_text().into()]);
    let parsed = Options::parse(&approved)?;
    assert_eq!(parsed.approve, Some(parsed.approval()));
    Ok(())
}
#[test]
fn implicit_native_limit_changes_cannot_reuse_an_approval() -> TestResult {
    let options = Options::parse(&arguments())?; let original = options.approval();
    for index in 0..8 {
        let mut changed = Options::parse(&arguments())?;
        match index {
            0 => changed.native.http.header_bytes -= 1,
            1 => changed.native.http.fragment_bytes -= 1,
            2 => changed.native.http.chunk_bytes -= 1,
            3 => changed.native.http.chunks -= 1,
            4 => changed.native.multipart.header_bytes -= 1,
            5 => changed.native.multipart.wrapper_bytes -= 1,
            6 => changed.native.source_runs -= 1,
            _ => changed.archive.maximum_scan_roots -= 1,
        }
        assert_ne!(original, changed.approval());
    }
    Ok(())
}
#[test]
fn aggregate_ceiling_is_checked_before_connect_and_cannot_be_per_slot_only() -> TestResult {
    let mut args = arguments();
    args.extend(["--max-reads".into(), "4096".into()]);
    assert!(Options::parse(&args).is_err());
    let mut args = arguments();
    args.extend(["--max-source-bytes".into(), (256 * 1024 * 1024_u64).to_string().into()]);
    assert!(Options::parse(&args).is_err());
    let mut args = arguments();
    let generations = (1..=32).map(|n| n.to_string()).collect::<Vec<_>>().join(",");
    replace(&mut args, "--generations", &generations)?;
    args.extend(["--max-reads".into(), "256".into(), "--max-source-bytes".into(), "16777216".into()]);
    assert_eq!(Options::parse(&args)?.recording()?.reservation().connections, 32);
    replace(&mut args, "--generations", &(generations + ",33"))?;
    assert!(Options::parse(&args).is_err());
    Ok(())
}
#[test]
fn malformed_paths_credentials_duplicate_options_and_budget_resets_are_rejected() -> TestResult {
    for (key, value) in [("--peer", "camera.invalid:80"), ("--peer", "0.0.0.0:80"),
        ("--peer", "127.0.0.1:0"), ("--target", "/stream?token=secret"),
        ("--target", "//elsewhere"), ("--host", "user:password@camera"),
        ("--root", "/tmp/../other"), ("--root", "/"), ("--plaintext", "no")] {
        let mut args = arguments(); replace(&mut args, key, value)?;
        assert!(Options::parse(&args).is_err(), "{key}");
    }
    for extra in [vec!["--approve"], vec!["--host", "duplicate"], vec!["--generation", "1"],
        vec!["--force", "yes"], vec!["--after-complete", "maybe"], vec!["--max-source-work", "0"],
        vec!["--initial-backoff-ms", "5001"], vec!["--stop-after-frames", "385"],
        vec!["--reset-budget", "yes"]] {
        let mut args = arguments(); args.extend(extra.into_iter().map(OsString::from));
        assert!(Options::parse(&args).is_err());
    }
    Ok(())
}
