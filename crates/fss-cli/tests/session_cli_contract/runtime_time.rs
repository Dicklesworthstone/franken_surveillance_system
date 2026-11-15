#![forbid(unsafe_code)]
//! Exercise the exact live dispatcher with an explicitly owned clock; request schemas stay fixed.

use std::cell::Cell;

use super::*;
use fss_cli::{execute_fss_with_time, execute_live_fss_with_exit, parse_fss_args};
use fss_core::{PrincipalId, TimestampNs};
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, SessionRecoveryState, inspect_session_bytes,
};
use fss_reference::agent_session::work_claims::WorkClaimLimits;
use fss_reference::deployment_session::{SessionTimeAuthority, SessionTimeError};

const START: i128 = 1_800_000_000_000_000_000;

struct Clock(Cell<Result<TimestampNs, SessionTimeError>>);

impl SessionTimeAuthority for Clock {
    fn observe(&self, _: &Path, _: &PrincipalId) -> Result<TimestampNs, SessionTimeError> {
        self.0.get()
    }
}

fn command(root: &Path, args: &[&str]) -> TestResult<fss_cli::FssCommand> {
    let mut argv: Vec<_> = args.iter().map(OsString::from).collect();
    argv.extend([
        OsString::from("--json"),
        OsString::from("--root"),
        root.as_os_str().to_owned(),
    ]);
    Ok(parse_fss_args(argv)?)
}

fn opening(root: &Path) -> TestResult<fss_cli::FssCommand> {
    command(
        root,
        &[
            "session",
            "open",
            "--mission-text",
            MISSION,
            "--objective",
            OBJECTIVE,
        ],
    )
}

fn state(root: &Path) -> TestResult<SessionRecoveryState> {
    Ok(inspect_session_bytes(
        &fs::read(root.join("agent/sessions/journal.fssj"))?,
        DurableSessionLimits::default(),
        WorkClaimLimits::default(),
    )?)
}

#[test]
fn live_dispatcher_expires_an_unchanged_deployment_and_refuses_cold_time_rollback() -> TestResult {
    let directory = OwnedDirectory::new("clock-dispatch-expiry")?;
    let root = empty_deployment(&directory, SITE)?;
    let authority = authority_tree(&root)?;
    let clock = Clock(Cell::new(Ok(TimestampNs(START))));
    let (body, exit) = execute_fss_with_time(opening(&root)?, &clock);
    assert_eq!(exit, fss_cli::ExitIdentity::SUCCESS, "{body}");
    let opened = state(&root)?;
    assert_eq!(opened.sessions.len(), 1);
    let session = &opened.sessions[0].session;
    assert_eq!(session.created_at_ns, START);
    let args = ["orient", "--session", session.session_id.as_str()];
    clock.0.set(Ok(TimestampNs(START + 1_000)));
    let (body, exit) = execute_fss_with_time(command(&root, &args)?, &clock);
    assert_eq!(exit, fss_cli::ExitIdentity::SUCCESS, "{body}");
    assert_eq!(
        state(&root)?.sessions[0].last_observed_at,
        TimestampNs(START + 1_000)
    );

    clock.0.set(Ok(TimestampNs(session.expires_at_ns)));
    let (body, exit) = execute_fss_with_time(command(&root, &args)?, &clock);
    assert_ne!(exit, fss_cli::ExitIdentity::SUCCESS);
    assert_eq!(Json::parse(&body)?.get("payload")?, &Json::Null);
    assert!(body.contains("ERR-AGENT-SESSION-NOT-FOUND-001"), "{body}");
    assert!(!body.contains(MISSION));
    let expired = state(&root)?;
    assert!(expired.sessions[0].closed);
    let cold = Clock(Cell::new(Ok(TimestampNs(START + 1))));
    let (body, exit) = execute_fss_with_time(opening(&root)?, &cold);
    assert_ne!(exit, fss_cli::ExitIdentity::SUCCESS, "{body}");
    assert_eq!(state(&root)?, expired);
    assert_eq!(authority_tree(&root)?, authority);
    Ok(())
}

#[test]
fn live_dispatcher_refuses_clock_failure_and_backward_observation_without_disclosure() -> TestResult
{
    let directory = OwnedDirectory::new("clock-dispatch-refusal")?;
    let root = empty_deployment(&directory, SITE)?;
    let clock = Clock(Cell::new(Err(SessionTimeError::Uncertain)));
    let (body, exit) = execute_fss_with_time(opening(&root)?, &clock);
    assert_ne!(exit, fss_cli::ExitIdentity::SUCCESS);
    assert!(body.contains("ERR-CLOCK-UNCERTAIN-001"), "{body}");
    assert_eq!(Json::parse(&body)?.get("payload")?, &Json::Null);
    assert!(!root.join("agent").exists());

    clock.0.set(Ok(TimestampNs(START)));
    let (body, exit) = execute_fss_with_time(opening(&root)?, &clock);
    assert_eq!(exit, fss_cli::ExitIdentity::SUCCESS, "{body}");
    let before = state(&root)?;
    let session = before.sessions[0].session.session_id.as_str();
    clock.0.set(Ok(TimestampNs(START - 1)));
    let (body, exit) =
        execute_fss_with_time(command(&root, &["orient", "--session", session])?, &clock);
    assert_ne!(exit, fss_cli::ExitIdentity::SUCCESS);
    assert_eq!(Json::parse(&body)?.get("payload")?, &Json::Null);
    assert!(!body.contains(MISSION));
    assert_eq!(state(&root)?, before);
    Ok(())
}

#[test]
fn default_live_dispatch_samples_host_time_for_each_command_without_a_request_time_field()
-> TestResult {
    let directory = OwnedDirectory::new("clock-default-host")?;
    let root = empty_deployment(&directory, SITE)?;
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let (body, exit) = execute_live_fss_with_exit(opening(&root)?);
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    assert_eq!(exit, fss_cli::ExitIdentity::SUCCESS, "{body}");
    let original = state(&root)?;
    let session = &original.sessions[0].session;
    assert!(session.created_at_ns >= i128::try_from(before)?);
    assert!(session.created_at_ns <= i128::try_from(after)?);
    let (body, exit) = execute_live_fss_with_exit(command(
        &root,
        &["orient", "--session", session.session_id.as_str()],
    )?);
    assert_eq!(exit, fss_cli::ExitIdentity::SUCCESS, "{body}");
    assert!(state(&root)?.sessions[0].last_observed_at.0 >= session.created_at_ns);
    assert!(
        command(
            &root,
            &[
                "orient",
                "--session",
                session.session_id.as_str(),
                "--now",
                "0"
            ]
        )
        .is_err()
    );
    Ok(())
}
