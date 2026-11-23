#![forbid(unsafe_code)]
//! Selected private reads keep the transport owner through native admission and final output.

use super::*;

use fss_cli::{ExitIdentity, RequestControl, execute_live_fss_with_control, parse_fss_args};
use fss_core::{PrincipalId, SessionId, TimestampNs};
use fss_reference::deployment_session::learning::{
    InspectLearningRequest, inspect_learning_cancellable,
};
use fss_reference::deployment_session::{
    DeploymentSessionError, SessionContext, SessionTimeAuthority, SessionTimeError,
};

#[test]
fn selected_learning_cancellation_covers_current_retained_and_context_refusal_reads() -> TestResult
{
    let (directory, event) = corroborated_event("learning-request-cancellation")?;
    let captured = capture(&directory, &event)?;
    let replacement =
        historical::open_selected_mission(&directory, &captured.principal, CAPTURE_OBJECTIVE)?;
    assert_ne!(replacement.session, captured.agent.session);
    let before = clock_independent_tree(&captured.agent.root)?;
    let elsewhere = directory.0.join("cancelled-learning-deployment");

    for agent in [&captured.agent, &replacement] {
        for tokens in ["16000", "1"] {
            let selected_args = args(agent, captured.root, &["--budget-tokens", tokens]);
            let command = || parse_fss_args(selected_args.clone());
            let probes = AtomicUsize::new(0);
            let never = || {
                probes.fetch_add(1, Ordering::AcqRel);
                false
            };
            let original = execute_live_fss_with_control(command()?, &RequestControl::new(&never))
                .ok_or("selected learning did not start")?;
            let expected = parse(&original.0)?;
            if tokens == "16000" {
                assert_eq!(original.1, ExitIdentity::SUCCESS, "{}", original.0);
                assert_selected_for(&expected, &captured, agent)?;
            } else {
                assert_eq!(original.1, ExitIdentity::AGENT_REFUSED, "{}", original.0);
                assert_eq!(text(&expected, &["outcome"])?, "refused");
            }
            let checkpoints = probes.load(Ordering::Acquire);
            assert!(
                checkpoints > 8,
                "selected learning lost its native checkpoints"
            );

            for cut in [1, checkpoints / 2, checkpoints - 1] {
                let probes = AtomicUsize::new(0);
                let moved = AtomicBool::new(false);
                let cancelled = || {
                    let observed = probes.fetch_add(1, Ordering::AcqRel);
                    if observed == cut && cut == checkpoints - 1 {
                        moved.store(
                            fs::rename(&agent.root, &elsewhere).is_ok(),
                            Ordering::Release,
                        );
                    }
                    observed >= cut
                };
                let (body, exit) =
                    execute_live_fss_with_control(command()?, &RequestControl::new(&cancelled))
                        .ok_or("started learning read lost its cancellation")?;
                if moved.load(Ordering::Acquire) {
                    fs::rename(&elsewhere, &agent.root)?;
                }
                assert_eq!(exit, ExitIdentity::AGENT_REFUSED, "{body}");
                assert!(!body.contains("PRIVATE_LEARNING_CANDIDATE_91c"), "{body}");
                assert!(
                    !body.contains(fss_cli::ERR_DOCTOR_NOT_A_DEPLOYMENT),
                    "{body}"
                );
                assert!(!body.contains("ERR-CLOCK-UNCERTAIN"), "{body}");
                let value = parse(&body)?;
                if cut == checkpoints - 1 {
                    assert!(
                        moved.load(Ordering::Acquire),
                        "final probe was never reached"
                    );
                    assert_eq!(text(&value, &["outcome"])?, "cancelled");
                    assert_eq!(field(&value, &["payload"])?, &Value::Null);
                    assert_eq!(field(&value, &["errorId"])?, &Value::Null);
                    assert_eq!(
                        field(&value, &["inputAnchor"])?,
                        field(&expected, &["inputAnchor"])?
                    );
                    assert!(body.contains("no storage was reread"), "{body}");
                    assert!(body.contains("not rolled back"), "{body}");
                } else {
                    assert!(
                        body.contains(fss_cli::ERR_CLI_READ_CANCELLED)
                            || body.contains("\"outcome\":\"cancelled\""),
                        "{body}",
                    );
                }
                assert_eq!(clock_independent_tree(&agent.root)?, before);
            }
        }
    }
    assert_eq!(captured.relay.connections(), 0);
    Ok(())
}

#[test]
fn cancellation_during_clock_admission_keeps_the_completed_native_watermark() -> TestResult {
    let (directory, event) = corroborated_event("learning-clock-cancellation")?;
    let captured = capture(&directory, &event)?;
    let before = clock_independent_tree(&captured.agent.root)?;
    let journal = captured.agent.root.join("agent/sessions/journal.fssj");
    let previous_journal = fs::read(&journal)?;
    let cancelled = AtomicBool::new(false);
    struct Clock<'a> {
        now: TimestampNs,
        cancelled: &'a AtomicBool,
        samples: AtomicUsize,
    }
    impl SessionTimeAuthority for Clock<'_> {
        fn observe(&self, _: &Path, _: &PrincipalId) -> Result<TimestampNs, SessionTimeError> {
            self.samples.fetch_add(1, Ordering::AcqRel);
            self.cancelled.store(true, Ordering::Release);
            Ok(self.now)
        }
    }
    let clock = Clock {
        now: TimestampNs(now_ns()?),
        cancelled: &cancelled,
        samples: AtomicUsize::new(0),
    };
    let observed = std::cell::RefCell::new(None);
    let inspection = inspect_learning_cancellable(
        SessionContext::runtime(&captured.agent.root, &clock),
        &InspectLearningRequest {
            session_id: SessionId::parse(&captured.agent.session)?,
            principal: PrincipalId::parse(&captured.principal)?,
            publication_root: captured.root,
            view: fss_core::AgentView::Forensic,
            budget_tokens: Some(16000),
        },
        &|| cancelled.load(Ordering::Acquire),
        |anchor, _| *observed.borrow_mut() = Some(anchor.clone()),
    );
    assert!(matches!(
        inspection,
        Err(DeploymentSessionError::Time(SessionTimeError::Cancelled))
    ));
    assert!(
        observed.borrow().is_some(),
        "the complete anchor must survive admission failure"
    );
    assert_eq!(clock.samples.load(Ordering::Acquire), 1);
    assert_ne!(
        fs::read(&journal)?,
        previous_journal,
        "the admitted clock was rolled back"
    );
    assert_eq!(clock_independent_tree(&captured.agent.root)?, before);
    assert_eq!(captured.relay.connections(), 0);
    Ok(())
}
