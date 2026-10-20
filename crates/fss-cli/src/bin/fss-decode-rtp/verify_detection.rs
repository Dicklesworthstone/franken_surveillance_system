#![forbid(unsafe_code)]
//! Cold verification reuses the exact report emitter with a read-only comparison sink.
use super::report_verification::{VerificationPath, arguments};
use super::*;

pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    if args.first().and_then(|v| v.to_str()) != Some("verify-detections") {
        return None;
    }
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        let help = "fss-decode-rtp verify-detections --root DIR --site SITE --source-root sha256:HEX\n\
  --custody current --package FILE --package-sha256 sha256:HEX\n\
  --report-in FILE --report-sha256 sha256:HEX\n\
  Supply the same explicit native decode, model threshold and report options as export.\n\
  --max-report-bytes bounds reads/comparison; no output paths are accepted.\n\
  Only complete fresh native reproduction plus independent SHA-256 and exact EOF verifies.\n";
        return Some(match io::stdout().lock().write_all(help.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        });
    }
    let parsed = arguments(args, "detect")
        .map_err(|reason| (ERR_CLI_MALFORMED_VALUE, reason))
        .and_then(|(native, expected)| super::parse(&native).map(|options| (options, expected)));
    Some(match parsed {
        Err((id, reason)) => {
            eprintln!("{id}: {reason}");
            ExitCode::from(2)
        }
        Ok((DetectOptions { base, settings }, expected)) => {
            let mut out = io::stdout().lock();
            let result = super::super::run_with(base, &mut out, |base, root, cx, out| {
                let input = VerificationPath::prepare(
                    &settings.report,
                    expected,
                    settings.max_report_bytes,
                    cx,
                )?;
                let scalar = ScalarExecCx::new();
                // Suppress export-specific status: only this caller can report verification.
                // The exact producer still decides native completeness, emits all rows and
                // retains every source refusal; saved JSON never supplies interpretation.
                let result = super::execute_inner(
                    base,
                    &settings,
                    root,
                    cx,
                    &scalar,
                    &input,
                    &mut io::sink(),
                );
                scalar.drain_and_finalize();
                result?;
                let bytes = input
                    .verified_bytes()
                    .ok_or_else(|| failure("verification did not finish"))?;
                writeln!(
                    out,
                    "operation=verify_detections\ndetection_report_verified=true\nverified_report_bytes={bytes}\nverified_report_sha256={expected}\nabsence_certifiable=false\neffect_authority=false"
                )?;
                Ok(())
            });
            match result {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(error) => {
                    let _ = writeln!(out, "detection_report_verified=false");
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
                }
            }
        }
    })
}
