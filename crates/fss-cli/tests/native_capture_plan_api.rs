#![forbid(unsafe_code)]
//! The shared planning API must agree with the real native command, including every
//! effective default and approval byte. Planning uses nonexistent private paths.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use fss_cli::capture_plan::{prepare_jpeg, prepare_rtsp};
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

fn jpeg_args() -> Vec<OsString> {
    let mut jpeg: Vec<_> = args("avc")
        .chunks_exact(2)
        .filter(|pair| {
            ![
                "--pins",
                "--frame-duration-ticks",
                "--codec",
                "--timing-evidence",
                "--journal-id",
            ]
            .iter()
            .any(|key| pair[0] == *key)
        })
        .flat_map(|pair| pair.iter().cloned())
        .collect();
    jpeg.extend([
        "--retention-evidence".into(),
        ContentDigest::sha256(b"operator-retention-declaration")
            .to_text()
            .into(),
    ]);
    jpeg
}

fn replace(args: &mut [OsString], key: &str, value: &str) -> Test {
    let index = args
        .iter()
        .position(|arg| arg == key)
        .ok_or("missing option")?;
    args[index + 1] = value.into();
    Ok(())
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

#[test]
fn jpeg_plans_match_real_cli_for_defaults_limits_and_unread_digest_credentials() -> Test {
    let nonexistent = PathBuf::from("/fss-plan-only-nonexistent");
    assert!(!nonexistent.exists());
    for authenticated in [false, true] {
        for overridden in [false, true] {
            let mut args = jpeg_args();
            if authenticated {
                for (key, value) in [
                    (
                        "--credential-file",
                        "/fss-plan-only-nonexistent/credentials",
                    ),
                    ("--auth-realm", "owner-declared-jpeg-realm"),
                    ("--legacy-md5", "yes"),
                    ("--legacy-no-qop", "yes"),
                ] {
                    args.extend([key.into(), value.into()]);
                }
            }
            if overridden {
                replace(&mut args, "--stop-after-pictures", "256")?;
                for (key, value) in [
                    ("--payload-type", "97"),
                    ("--media-index", "15"),
                    ("--rtp-channel", "4"),
                    ("--read-bytes", "2048"),
                    ("--max-datagrams", "64"),
                    ("--max-dimension", "1024"),
                    ("--timeout-ms", "45000"),
                ] {
                    args.extend([key.into(), value.into()]);
                }
            }
            let shared = prepare_jpeg(&args)?;
            let output = Command::new(binary()?).arg("jpeg").args(&args).output()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stderr.is_empty());
            assert_eq!(output.stdout, (shared.preview.clone() + "\n").into_bytes());
            assert!(shared.preview.contains(&shared.approval.to_text()));
            assert!(shared.preview.contains("\"mode\":\"capture\""));
            assert!(!shared.preview.contains("owner-declared-jpeg-realm"));
            if authenticated {
                assert!(shared.preview.contains("\"credentials_read\":false"));
            }
        }
    }
    assert!(
        !nonexistent.exists(),
        "pure planning created an output or credential path"
    );
    Ok(())
}

#[test]
fn jpeg_planning_refuses_execution_replay_foreign_flags_and_native_bound_violations() -> Test {
    let base = jpeg_args();
    let approval = prepare_jpeg(&base)?.approval;
    for (key, value) in [
        ("--approve", approval.to_text()),
        ("--pins", "/nonexistent/pins".into()),
        ("--codec", "jpeg".into()),
        ("--frame-duration-ticks", "3600".into()),
        ("--prefix-head", approval.to_text()),
        ("--media-index", "16".into()),
        ("--unknown", "PRIVATE_REJECTED_ARGUMENT".into()),
        ("--peer", "127.0.0.1:8554".into()),
    ] {
        let mut args = base.clone();
        args.extend([key.into(), value.into()]);
        let error = prepare_jpeg(&args)
            .err()
            .ok_or("invalid JPEG option accepted")?;
        assert!(!error.contains("PRIVATE_REJECTED_ARGUMENT"));
    }
    let mut replay = vec!["replay".into()];
    replay.extend(base.iter().cloned());
    assert!(prepare_jpeg(&replay).is_err());
    for (key, value) in [
        ("--ssrc", "0"),
        ("--ssrc", "auto"),
        ("--stop-after-pictures", "257"),
        ("--authority", "PRIVATE_PASSWORD@camera.test"),
    ] {
        let mut args = base.clone();
        replace(&mut args, key, value)?;
        let error = prepare_jpeg(&args)
            .err()
            .ok_or("invalid JPEG value accepted")?;
        assert!(!error.contains("PRIVATE_PASSWORD"));
    }
    let mut oversized = base.clone();
    replace(
        &mut oversized,
        "--presentation",
        &format!("/{}", "x".repeat(4096)),
    )?;
    assert!(prepare_jpeg(&oversized).is_err());
    assert!(prepare_jpeg(&vec![OsString::from("--peer"); 122]).is_err());
    assert!(prepare_jpeg(&base[..base.len() - 1]).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut non_utf8 = base;
        non_utf8[1] = OsString::from_vec(vec![b'/', 0xff]);
        assert!(prepare_jpeg(&non_utf8).is_err());
    }
    Ok(())
}
