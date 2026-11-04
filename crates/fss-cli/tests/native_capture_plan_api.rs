#![forbid(unsafe_code)]
//! The shared planning API must agree with the real native command, including every
//! effective default and approval byte. Planning uses nonexistent private paths.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use fss_cli::capture_plan::prepare_rtsp;
use fss_core::ContentDigest;

type Test<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn args(codec: &str) -> Vec<OsString> {
    let mut args = Vec::new();
    for (key, value) in [
        ("--root", "/fss-plan-only-nonexistent/archive"),
        ("--pins", "/fss-plan-only-nonexistent/pins"),
        ("--peer", "127.0.0.1:8554"),
        ("--authority", "camera.test:8554"),
        ("--presentation", "/camera/main"),
        ("--control-root", "/camera"),
        ("--sensor-id", "sensor:site-compile-fixture"),
        ("--stream-id", "stream:site-compile-fixture"),
        ("--generation", "1"),
        ("--ingress", "1"),
        ("--ssrc", "7"),
        ("--frame-duration-ticks", "3600"),
        ("--stop-after-pictures", "2"),
        ("--codec", codec),
        ("--owner-authorized", "yes"),
        ("--plaintext", "yes"),
        ("--retain-originals", "yes"),
    ] {
        args.extend([key.into(), value.into()]);
    }
    for key in [
        "--anchor",
        "--receive-clock",
        "--timing-evidence",
        "--journal-id",
    ] {
        args.extend([
            key.into(),
            ContentDigest::sha256(key.as_bytes()).to_text().into(),
        ]);
    }
    args
}

fn binary() -> Test<PathBuf> {
    std::env::var_os("FSS_CAPTURE_RTSP_BIN")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_fss-capture-rtsp").map(PathBuf::from))
        .ok_or_else(|| "native capture binary is required for plan equivalence".into())
}

#[test]
fn shared_plans_match_real_cli_for_avc_hevc_and_digest_authentication() -> Test {
    for codec in ["avc", "hevc"] {
        for authenticated in [false, true] {
            let mut args = args(codec);
            if authenticated {
                for (key, value) in [
                    (
                        "--credential-file",
                        "/fss-plan-only-nonexistent/credentials",
                    ),
                    ("--auth-realm", "owner-declared-realm"),
                    ("--legacy-md5", "yes"),
                    ("--keepalive-method", "get-parameter"),
                ] {
                    args.extend([key.into(), value.into()]);
                }
            }
            let shared = prepare_rtsp(&args)?;
            let output = Command::new(binary()?).args(&args).output()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, (shared.preview.clone() + "\n").into_bytes());
            assert!(shared.preview.contains(&shared.approval.to_text()));
            assert!(!shared.preview.contains("owner-declared-realm"));
            assert!(!shared.preview.contains("--approve"));
        }
    }
    Ok(())
}

#[test]
fn planning_adapter_refuses_execution_and_does_not_echo_rejected_values() -> Test {
    let mut input = args("avc");
    let approval = prepare_rtsp(&input)?.approval;
    input.extend(["--approve".into(), approval.to_text().into()]);
    assert!(prepare_rtsp(&input).is_err());
    input.truncate(input.len() - 2);
    let position = input
        .iter()
        .position(|value| value == "--authority")
        .ok_or("authority")?;
    input[position + 1] = "CANARY_PASSWORD@camera.test".into();
    let error = prepare_rtsp(&input)
        .err()
        .ok_or("invalid authority accepted")?;
    assert!(!error.contains("CANARY_PASSWORD"));
    Ok(())
}
