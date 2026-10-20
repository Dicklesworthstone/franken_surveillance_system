#![forbid(unsafe_code)]
//! Verify every tracking row against fresh source/decode/inference/association ownership.
use super::super::detect_cmd::report_verification::{VerificationPath, arguments};
use super::*;

#[path = "tracking_route.rs"]
mod tracking_route;

pub(super) fn dispatch(args: &[OsString]) -> Option<ExitCode> {
    if !tracking_route::is_report_verification(args) {
        return None;
    }
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        let help = "fss-decode-rtp verify-track-report --root DIR --site SITE --source-root sha256:HEX\n\
  --custody current --package FILE --package-sha256 sha256:HEX --class-index N\n\
  --report-in FILE --report-sha256 sha256:HEX\n\
  Supply the same explicit native decode, model threshold and class/tracker options as export.\n\
  --max-report-bytes bounds reads/comparison; no output paths are accepted.\n\
  Only complete fresh native reproduction plus independent SHA-256 and exact EOF verifies.\n\
  verify-tracks with --report-in/--report-sha256 remains a report-verification alias.\n\
  verify-tracks with --tracks-in/--tracks-sha256 retains the original trajectory protocol.\n";
        return Some(match io::stdout().lock().write_all(help.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        });
    }
    let parsed = arguments(args, "track")
        .map_err(|reason| (ERR_CLI_MALFORMED_VALUE, reason))
        .and_then(|(native, expected)| super::parse(&native).map(|options| (options, expected)));
    Some(match parsed {
        Err((id, reason)) => {
            eprintln!("{id}: {reason}");
            ExitCode::from(2)
        }
        Ok((TrackOptions { base, settings }, expected)) => {
            let mut out = io::stdout().lock();
            let result = super::super::run_with(base, &mut out, |base, root, cx, out| {
                let report = settings
                    .report
                    .as_deref()
                    .ok_or_else(|| failure("verification input required"))?;
                let input =
                    VerificationPath::prepare(report, expected, settings.max_report_bytes, cx)?;
                let scalar = ScalarExecCx::new();
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
                    "operation=verify_tracks\ntracking_report_verified=true\nverified_report_bytes={bytes}\nverified_report_sha256={expected}\nidentity_authority=false\nabsence_certifiable=false\neffect_authority=false"
                )?;
                Ok(())
            });
            match result {
                Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
                Err(error) => {
                    let _ = writeln!(out, "tracking_report_verified=false");
                    eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
                    ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
                }
            }
        }
    })
}
