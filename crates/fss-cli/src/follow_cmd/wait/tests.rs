#![forbid(unsafe_code)]

use std::ffi::OsString;

use super::*;

const ANCHOR: &str =
    "anchor:0123456789abcdef:3:e2:abababababababababababababababababababababababababababababababab";

fn parse(extra: &[&str]) -> Result<FollowArgs, crate::CliError> {
    let mut args = vec![
        "session",
        "follow",
        "--json",
        "--root",
        "/does-not-exist",
        "--since",
        ANCHOR,
    ];
    args.extend_from_slice(extra);
    match crate::parse_fss_args(args.into_iter().map(OsString::from))? {
        crate::FssCommand::Follow(args) => Ok(args),
        _ => unreachable!("follow parser returned another command"),
    }
}

#[test]
fn wait_is_explicit_bounded_and_excludes_continuation_before_io()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(parse(&[])?.wait_ms, None);
    assert_eq!(parse(&["--wait-ms", "1"])?.wait_ms, Some(1));
    assert_eq!(parse(&["--wait-ms=10000"])?.wait_ms, Some(10_000));
    for extra in [
        vec!["--wait-ms", "0"],
        vec!["--wait-ms", "10001"],
        vec!["--wait-ms", "-1"],
        vec!["--wait-ms", "1.5"],
        vec!["--wait-ms", "1000", "--continuation", "continuation:exact"],
        vec!["--continuation", "continuation:exact", "--wait-ms", "1000"],
        vec!["--wait-ms", "10", "--wait-ms", "20"],
    ] {
        assert!(parse(&extra).is_err(), "{extra:?}");
    }
    Ok(())
}

#[test]
fn absent_wait_retains_exact_legacy_request_bytes_and_present_bounds_are_bound()
-> Result<(), Box<dyn std::error::Error>> {
    let args = parse(&["--view", "brief", "--max-entries", "2"])?;
    let head = LedgerAnchor::genesis("site:wait-request");
    let legacy = request_identity("fss.cli.follow.request.v1", |encoder| {
        encoder.text(args.since.as_str());
        encoder.text(args.view.id());
        args.principal.encode_canonical(encoder);
        encoder.u64(2);
        encoder.bool(false);
        head.encode_canonical(encoder);
    });
    assert_eq!(request_digest(&args, &head), legacy);
    let mut waited = args.clone();
    waited.wait_ms = Some(1_000);
    let one = request_digest(&waited, &head);
    assert_ne!(one, legacy);
    let bound = request_identity("fss.cli.follow.request.v1", |encoder| {
        encoder.text(args.since.as_str());
        encoder.text(args.view.id());
        args.principal.encode_canonical(encoder);
        encoder.u64(2);
        encoder.bool(false);
        head.encode_canonical(encoder);
        encoder.text("bounded_wait_ms");
        encoder.u64(1_000);
        encoder.u64(u64::from(MAX_FOLLOW_WAIT_READS));
        encoder.u64(u64::from(
            fss_reference::agent_follow::wait::MAX_FOLLOW_WAIT_SOURCE_READS,
        ));
        encoder.u64(fss_reference::agent_follow::wait::MAX_FOLLOW_WAIT_SOURCE_ENVELOPE_BYTES);
    });
    assert_eq!(
        one, bound,
        "the admitted source limits are part of the wait identity"
    );
    waited.wait_ms = Some(2_000);
    assert_ne!(request_digest(&waited, &head), one);
    Ok(())
}

#[test]
fn explicit_control_entrypoint_never_falls_through_to_ambient_io()
-> Result<(), Box<dyn std::error::Error>> {
    struct Denied {
        checkpoints: u32,
    }
    impl FollowWaitControl for Denied {
        fn checkpoint(
            &mut self,
            _: &FollowWaitBinding,
            _: FollowWaitBoundary,
        ) -> Result<u64, FollowWaitDenial> {
            self.checkpoints += 1;
            Err(FollowWaitDenial::Unauthorized)
        }
        fn park(&mut self, _: &FollowWaitBinding, _: u64) -> Result<(), FollowWaitDenial> {
            Err(FollowWaitDenial::Unauthorized)
        }
    }
    let args = parse(&[])?;
    let mut control = Denied { checkpoints: 0 };
    let (body, exit) = execute_follow_with_control(&args, &mut control);
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert!(body.contains(crate::ERR_CLI_MALFORMED_VALUE));
    assert_eq!(
        control.checkpoints, 0,
        "missing wait is refused before admission or I/O"
    );
    let args = parse(&["--wait-ms", "1000"])?;
    let (body, exit) = execute_follow_with_control(&args, &mut control);
    assert_eq!(exit, ExitIdentity::AGENT_REFUSED);
    assert!(body.contains(ERR_AUTH));
    assert_eq!(control.checkpoints, 1);
    Ok(())
}
