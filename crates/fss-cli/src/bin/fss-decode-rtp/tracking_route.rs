#![forbid(unsafe_code)]
//! Select the report verifier without intercepting the older trajectory protocol.

use std::ffi::OsString;

/// The explicit name is unambiguous. Keep the recently introduced report form of
/// `verify-tracks` as an option-key-selected alias, never a file-content heuristic.
/// The selected owner still performs all syntax, bounds and mode admission.
pub(super) fn is_report_verification(args: &[OsString]) -> bool {
    match args.first().and_then(|arg| arg.to_str()) {
        Some("verify-track-report") => true,
        Some("verify-tracks") => args[1..]
            .chunks(2)
            .take(128)
            .any(|pair| matches!(pair[0].to_str(), Some("--report-in" | "--report-sha256"))),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(args: &[&str]) -> bool {
        is_report_verification(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn explicit_report_name_and_report_alias_reach_the_same_owner() {
        assert!(route(&["verify-track-report"]));
        assert!(route(&["verify-track-report", "--help"]));
        assert!(route(&["verify-tracks", "--report-in", "report.jsonl"]));
        assert!(route(&[
            "verify-tracks",
            "--report-sha256",
            "sha256:expected"
        ]));
    }

    #[test]
    fn original_trajectory_and_its_help_remain_reachable() {
        assert!(!route(&["verify-tracks", "--tracks-in", "tracks.bin"]));
        assert!(!route(&[
            "verify-tracks",
            "--tracks-sha256",
            "sha256:expected"
        ]));
        assert!(!route(&["verify-tracks", "--completion", "diagnostic"]));
        assert!(!route(&["verify-tracks", "--help"]));
        assert!(!route(&["verify-tracks", "-h"]));
        assert!(!route(&["verify-tracks"]));
    }

    #[test]
    fn option_values_cannot_select_a_different_protocol() {
        for value in ["--report-in", "--report-sha256", "verify-track-report"] {
            assert!(!route(&["verify-tracks", "--tracks-in", value]));
            assert!(!route(&[
                "verify-tracks",
                "--root",
                value,
                "--tracks-in",
                "input"
            ]));
        }
    }

    #[test]
    fn unrelated_commands_never_reach_report_verification() {
        for name in [
            "track",
            "track-stream",
            "verify-receipts",
            "detect",
            "cascade",
        ] {
            assert!(!route(&[name, "--report-in", "input"]));
        }
        assert!(!route(&[]));
    }

    #[test]
    fn missing_report_value_is_refused_by_the_report_owner() {
        assert!(route(&["verify-tracks", "--report-in"]));
        assert!(route(&[
            "verify-tracks",
            "--root",
            "root",
            "--report-sha256"
        ]));
    }

    #[test]
    fn mixed_protocols_cannot_fall_back_to_trajectory_verification() {
        assert!(route(&[
            "verify-tracks",
            "--tracks-in",
            "a",
            "--report-in",
            "b"
        ]));
        assert!(route(&[
            "verify-tracks",
            "--report-in",
            "a",
            "--tracks-in",
            "b"
        ]));
    }

    #[test]
    fn native_path_values_do_not_need_unicode() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let args = vec![
                OsString::from("verify-tracks"),
                OsString::from("--tracks-in"),
                OsString::from_vec(vec![0xff, 0xfe]),
            ];
            assert!(!is_report_verification(&args));
        }
    }

    #[test]
    fn routing_scan_is_bounded_before_the_selected_parser_rejects_oversized_input() {
        let mut args = vec![OsString::from("verify-tracks")];
        for _ in 0..128 {
            args.extend([OsString::from("--root"), OsString::from("unused")]);
        }
        args.extend([OsString::from("--report-in"), OsString::from("input")]);
        assert!(!is_report_verification(&args));
    }
}
