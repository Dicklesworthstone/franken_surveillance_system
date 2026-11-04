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
