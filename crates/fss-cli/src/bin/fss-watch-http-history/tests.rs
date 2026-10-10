#![forbid(unsafe_code)]
//! Pure approval boundaries and bounded operator output; native workflow lives in CLI integration.

use std::ffi::OsString;
use std::io::{self, Write};

use fss_core::ContentDigest;
use fss_reference::ingest::recorded_watch::WatchPlan;

use super::{driver, emit, plan::Options, rerun};

type Test = Result<(), Box<dyn std::error::Error>>;

fn args() -> Vec<OsString> {
    let session = ContentDigest::sha256(b"history-cli-session").to_text();
    let root = ContentDigest::sha256(b"history-cli-exact-root").to_text();
    [
        "--archive",
        "/unopened-history-watch-archive",
        "--root",
        "/unopened-history-watch-deployment",
        "--site",
        "site:history-watch",
        "--history-session",
        &session,
        "--history-root",
        &root,
        "--history-connections",
        "1",
        "--binding",
        "10,sensor:porch,stream:porch,50000000000,0,1000,10",
        "--interpretation",
        "gray",
        "--zone",
        "porch:0,0,48,32",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(Into::into)
    .collect()
}
fn replace(args: &mut [OsString], key: &str, value: &str) -> Result<(), &'static str> {
    let i = args
        .iter()
        .position(|a| a == key)
        .ok_or("missing test option")?;
    *args.get_mut(i + 1).ok_or("missing test option value")? = value.into();
    Ok(())
}

#[test]
fn exact_preview_and_mismatched_approval_require_no_existing_stores() -> Test {
    let mut options = Options::parse(&args())?;
    let preview = options.preview()?;
    assert!(preview.contains("\"writes\":\"none\""));
    assert!(preview.contains("\"connections\":1"));
    assert!(preview.contains("\"capture_time_label\":\"operator_assumptions_per_generation\""));
    assert!(preview.contains(&options.approval()?.to_text()));
    options.approve = Some(ContentDigest::sha256(b"another original retention plan"));
    assert_eq!(
        driver::execute(&options),
        Err("ERR-HTTP-HISTORY-WATCH-AUTHORITY-001")
    );
    Ok(())
}

#[test]
fn every_source_time_owner_analysis_and_budget_change_needs_new_approval() -> Test {
    let original = Options::parse(&args())?.approval()?;
    for (key, value) in [
        ("--archive", "/different-history-watch-archive"),
        ("--root", "/different-history-watch-deployment"),
        ("--site", "site:other"),
        (
            "--binding",
            "10,sensor:porch,stream:porch,50000000000,1,1000,10",
        ),
        (
            "--binding",
            "10,sensor:porch,stream:other,50000000000,0,1000,10",
        ),
        ("--zone", "porch:1,0,47,32"),
        ("--interpretation", "ycbcr"),
    ] {
        let mut altered = args();
        replace(&mut altered, key, value)?;
        assert_ne!(Options::parse(&altered)?.approval()?, original, "{key}");
    }
    for (key, value) in [
        ("--principal", "principal:other"),
        ("--max-work", "5000000000000"),
        ("--max-framing-work", "50000000000"),
        ("--timeout-ms", "60000"),
        ("--max-frames-per-generation", "129"),
        ("--max-history-reads", "4096"),
        ("--max-history-bytes", "268435456"),
        ("--work-units", "200000000"),
        ("--stream-read-bytes", "10000000"),
        ("--stream-pixel-budget", "10000000"),
        ("--stream-assignment-work", "10000000"),
        ("--stream-trace-bytes", "4000000"),
        ("--max-dimension", "2048"),
        ("--max-pixels", "1000000"),
        ("--pixel-threshold", "26"),
        ("--confirmation-hits", "4"),
        ("--screened", "yes"),
        ("--tolerate-decode-refusals", "yes"),
    ] {
        let mut altered = args();
        altered.extend([key.into(), value.into()]);
        assert_ne!(Options::parse(&altered)?.approval()?, original, "{key}");
    }
    Ok(())
}

#[test]
fn admission_requires_exact_complete_timing_and_refuses_unhandled_authority() -> Test {
    for value in [
        "10,sensor:porch,stream:porch,50000000000",
        "10,sensor:porch,stream:porch,50000000000,0,1000,NaN",
        "10,sensor:porch,stream:porch,50000000000,0,1000,0",
        "0,sensor:porch,stream:porch,50000000000,0,1000,10",
        "10,sensor:porch,stream:porch,50000000000,-1,1000,10",
    ] {
        let mut altered = args();
        replace(&mut altered, "--binding", value)?;
        assert!(Options::parse(&altered).is_err(), "{value}");
    }
    for (key, value) in [
        ("--approve", "sha256:00"),
        ("--retain-coverage", "yes"),
        ("--detector-package", "/model"),
        ("--screened", "true"),
        ("--owner-authorized", "no"),
    ] {
        let mut altered = args();
        altered.extend([key.into(), value.into()]);
        assert!(Options::parse(&altered).is_err(), "{key}");
    }
    let mut altered = args();
    replace(&mut altered, "--history-connections", "2")?;
    assert!(Options::parse(&altered).is_err());
    Ok(())
}

#[test]
fn reconnect_allocations_are_reserved_as_a_whole_and_commands_preserve_all_watch_inputs() -> Test {
    let one = Options::parse(&args())?;
    let mut two = args();
    replace(&mut two, "--history-connections", "2")?;
    two.extend([
        "--binding".into(),
        "20,sensor:porch,stream:porch,70000000000,6000000000,1000,10".into(),
    ]);
    let two = Options::parse(&two)?;
    let r1 = one.plan.reservation(&one.limits)?;
    let r2 = two.plan.reservation(&two.limits)?;
    assert_eq!(r2.connections, 2);
    assert_eq!(r2.frames, 2 * r1.frames);
    assert_eq!(r2.pixel_samples, 2 * r1.pixel_samples);
    assert_eq!(r2.jpeg_work, 2 * r1.jpeg_work);
    assert_eq!(r2.trace_bytes, 2 * r1.trace_bytes);
    let mut options = Options::parse(&args())?;
    options.root = "/history watch/'owner'".into();
    options.plan.options.tolerate_decode_refusals = true;
    options.plan.screened = true;
    let plan = WatchPlan {
        import_identity: ContentDigest::sha256(b"native imported response"),
        interpretation: options.plan.interpretation,
        first_segment: 0,
        segment_count: 300,
        zones: options.plan.zones.clone(),
        detector: options.plan.detector,
        tracker: options.plan.tracker,
    };
    options.limits.maximum_frames_per_generation = 300;
    let command = rerun::watch_command(&options, &plan)?;
    assert!(command.starts_with("fss-event watch --stream-watch "));
    assert!(command.contains("--segment-count 300"));
    assert!(command.contains("--root '/history watch/'\\''owner'\\'''"));
    assert!(command.contains("--sensor-health conservative-v1"));
    assert!(command.ends_with("--tolerate-decode-refusals"));
    assert!(command.contains(&format!(
        "--work-units {}",
        options.limits.watch.decode.jpeg_work_units
    )));
    assert!(!command.contains("--approve"));
    Ok(())
}

struct FailingSink {
    calls: usize,
}
impl Write for FailingSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        Err(io::ErrorKind::Interrupted.into())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn bounded_output_refuses_before_a_prefix_and_caps_interrupted_retries() -> Test {
    let mut bytes = Vec::new();
    assert!(emit(&mut bytes, "oversized", 3).is_err());
    assert!(bytes.is_empty());
    let mut sink = FailingSink { calls: 0 };
    assert!(emit(&mut sink, "{}", 4096).is_err());
    assert_eq!(sink.calls, 8);
    emit(&mut bytes, "{}", 4096)?;
    assert_eq!(bytes, b"{}\n");
    Ok(())
}
