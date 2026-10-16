#![forbid(unsafe_code)]
//! Exercise fusion option admission through the real binary, before deployment or model I/O.
//! These tests do not execute model inference or qualify deployment calibration.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_CASE: AtomicU64 = AtomicU64::new(0);
const PIN: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER_PIN: &str =
    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

struct Invocation {
    args: Vec<OsString>,
    root: PathBuf,
    report: PathBuf,
}

impl Invocation {
    fn new(command: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock is after the epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "fss-fusion-cli-{}-{nonce}-{}",
            std::process::id(),
            NEXT_CASE.fetch_add(1, Ordering::Relaxed),
        ));
        let report = root.with_extension("report.json");
        assert!(!root.exists());
        assert!(!report.exists());
        let mut invocation = Self {
            args: vec![command.into(), "--root".into(), root.clone().into_os_string()],
            root,
            report,
        };
        invocation.add(&["--site", "site:fusion-cli", "--interpretation", "gray"]);
        match command {
            "watch" => invocation.add(&[
                "--import-id",
                PIN,
                "--zone",
                "door:4,4,16,16",
            ]),
            "corroborate" => invocation.add(&[
                "--camera",
                &format!("east:{PIN}"),
                "--camera",
                &format!("west:{OTHER_PIN}"),
                "--ground",
                "east:1,0,0,0,1,0,0,0,1",
                "--ground",
                "west:1,0,0,0,1,0,0,0,1",
                "--zone",
                "door:4,4,16,16",
                "--time-gate-ns",
                "250000000",
                "--distance-gate",
                "16",
            ]),
            _ => panic!("unsupported fixture command"),
        }
        invocation.args.extend([
            "--report-out".into(),
            invocation.report.clone().into_os_string(),
        ]);
        invocation
    }

    fn add(&mut self, args: &[&str]) {
        self.args.extend(args.iter().map(|arg| OsString::from(*arg)));
    }

    fn detector(&mut self) {
        self.add(&[
            "--detector-package",
            "deliberately-unread-model.fss",
            "--detector-digest",
            PIN,
            "--detector-max-inferences",
            "2",
        ]);
    }

    fn fusion(&mut self) {
        self.add(&[
            "--fusion-profile",
            "deliberately-unread-profile.json",
            "--fusion-digest",
            PIN,
        ]);
    }

    fn refused(&self, reason: &str) {
        let output = Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(&self.args)
            .output()
            .expect("start the actual fss-event binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "request unexpectedly succeeded: {:?}",
            self.args,
        );
        assert!(
            stderr.contains(reason),
            "expected admission refusal {reason:?}, got {stderr:?}",
        );
        assert!(output.stdout.is_empty(), "a refused request emitted a report");
        assert!(!self.root.exists(), "admission touched the deployment root");
        assert!(!self.report.exists(), "admission created an export");
    }
}

#[test]
fn both_commands_require_a_detector_and_both_fusion_pins() {
    for command in ["watch", "corroborate"] {
        let mut missing_detector = Invocation::new(command);
        missing_detector.fusion();
        missing_detector.refused("--detector-package is required");

        let mut missing_digest = Invocation::new(command);
        missing_digest.detector();
        missing_digest.add(&["--fusion-profile", "profile.json"]);
        missing_digest.refused("required together");

        let mut missing_profile = Invocation::new(command);
        missing_profile.detector();
        missing_profile.add(&["--fusion-digest", PIN]);
        missing_profile.refused("required together");
    }
}

#[test]
fn malformed_and_duplicate_profile_pins_are_not_ignored() {
    for command in ["watch", "corroborate"] {
        let mut malformed = Invocation::new(command);
        malformed.detector();
        malformed.add(&[
            "--fusion-profile",
            "profile.json",
            "--fusion-digest",
            "not-a-digest",
        ]);
        malformed.refused("invalid digest for --fusion-digest");

        let mut duplicate = Invocation::new(command);
        duplicate.detector();
        duplicate.fusion();
        duplicate.add(&["--fusion-digest", OTHER_PIN]);
        duplicate.refused("duplicate --fusion-digest");
    }
}

#[test]
fn neither_command_can_publish_or_retain_authority_with_fusion() {
    for command in ["watch", "corroborate"] {
        for flag in ["--approve", "--retain-coverage", "--retain-health"] {
            let mut invocation = Invocation::new(command);
            invocation.detector();
            invocation.fusion();
            invocation.add(&[flag, OTHER_PIN]);
            invocation.refused("calibrated fusion is read-only");
        }
    }
}

#[test]
fn unsupported_streaming_modes_cannot_silently_drop_requested_fusion() {
    for (command, flags) in [
        (
            "watch",
            vec![
                "--stream-dwell",
                "--dwell-for-ns",
                "1000000000",
                "--dwell-max-gap-ns",
                "250000000",
            ],
        ),
        ("corroborate", vec!["--stream-corroborate"]),
    ] {
        let mut invocation = Invocation::new(command);
        invocation.detector();
        invocation.fusion();
        invocation.add(&flags);
        invocation.refused(if command == "watch" {
            "not streaming"
        } else {
            "not dwell or streaming"
        });
    }
}

#[test]
fn full_camera_fusion_still_requires_complete_valid_calibration_pins() {
    for (flags, reason) in [
        (vec!["--calibration", "calibration.json"], "go together"),
        (vec!["--calibration-digest", OTHER_PIN], "go together"),
        (
            vec!["--calibration", "calibration.json", "--calibration-digest", "invalid"],
            "invalid digest for --calibration-digest",
        ),
    ] {
        let mut invocation = Invocation::new("corroborate");
        invocation.detector();
        invocation.fusion();
        invocation.add(&flags);
        invocation.refused(reason);
    }
}

#[test]
fn full_camera_fusion_cannot_mix_advice_with_publication_or_retention() {
    for flag in ["--approve", "--retain-coverage", "--retain-health"] {
        let mut invocation = Invocation::new("corroborate");
        invocation.detector();
        invocation.fusion();
        invocation.add(&[
            "--calibration",
            "deliberately-unread-calibration.json",
            "--calibration-digest",
            OTHER_PIN,
            flag,
            PIN,
        ]);
        invocation.refused("calibrated fusion is read-only");
    }
}

#[test]
fn short_dwell_fusion_preserves_authority_and_temporal_refusals_before_io() {
    for flag in ["--approve", "--retain-coverage", "--retain-health"] {
        let mut invocation = Invocation::new("watch");
        invocation.detector();
        invocation.fusion();
        invocation.add(&[
            "--dwell-for-ns", "200000000", "--dwell-max-gap-ns", "100000000", flag, PIN,
        ]);
        invocation.refused("calibrated fusion is read-only");
    }
    let mut incomplete = Invocation::new("watch");
    incomplete.detector();
    incomplete.fusion();
    incomplete.add(&["--dwell-for-ns", "200000000"]);
    incomplete.refused("dwell requires both");

    let mut unsupported_health = Invocation::new("watch");
    unsupported_health.detector();
    unsupported_health.fusion();
    unsupported_health.add(&[
        "--dwell-for-ns", "200000000", "--dwell-max-gap-ns", "100000000",
        "--sensor-health", "conservative-v1",
    ]);
    unsupported_health.refused("short dwell screening is unsupported");
}
