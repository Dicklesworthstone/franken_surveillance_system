#![forbid(unsafe_code)]
//! Cross-mode tests remain with the executable; the pure planner has no executors.

use super::plan::tests::{args, set};

#[test]
fn automatic_ssrc_cannot_enter_unimplemented_source_retention_or_reconnect_identity_paths() {
    let mut source = args();
    set(&mut source, "--source-root", "/owner/private/datagrams");
    set(
        &mut source,
        "--source-retention-evidence",
        "sha256:5555555555555555555555555555555555555555555555555555555555555555",
    );
    assert!(super::source_mode::SourcePlan::parse(&source).is_ok());
    set(&mut source, "--ssrc", "auto");
    assert!(
        super::source_mode::SourcePlan::parse(&source)
            .err()
            .is_some_and(|error| error.contains("automatic SSRC"))
    );
    let mut reconnect = args();
    set(&mut reconnect, "--max-attempts", "2");
    set(&mut reconnect, "--retry-delay-ms", "1");
    set(&mut reconnect, "--retry-max-delay-ms", "2");
    assert!(super::reconnect::ReconnectPlan::parse(&reconnect).is_ok());
    set(&mut reconnect, "--ssrc", "auto");
    assert!(
        super::reconnect::ReconnectPlan::parse(&reconnect)
            .err()
            .is_some_and(|error| error.contains("automatic SSRC"))
    );
}


#[test]
fn recorder_replay_cannot_enter_wrapped_live_capture_or_recovery_paths() {
    let mut input = args();
    set(&mut input, "--replay-start", "20261101T120000Z");
    set(&mut input, "--replay-end", "20261101T120100Z");
    assert!(super::single::SinglePlan::parse(&input).is_ok());
    assert!(super::source_mode::SourcePlan::parse(&input).is_err());
    let mut reconnect = input.clone();
    set(&mut reconnect, "--max-attempts", "2");
    set(&mut reconnect, "--retry-delay-ms", "1");
    set(&mut reconnect, "--retry-max-delay-ms", "2");
    assert!(super::reconnect::ReconnectPlan::parse(&reconnect).is_err());
    assert!(super::from_onvif::SourcePlan::parse(&input).is_err());
    assert!(super::from_unifi::SourcePlan::parse(&input).is_err());
    assert!(super::sentinel::Options::parse(&input).is_err());
    for mode in ["yes", "index"] {
        let mut recovery = input.clone();
        set(&mut recovery, "--recover", mode);
        assert!(super::single::SinglePlan::parse(&recovery).is_err());
    }
}
