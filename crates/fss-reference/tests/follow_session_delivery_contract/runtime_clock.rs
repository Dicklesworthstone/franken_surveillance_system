#![forbid(unsafe_code)]
//! Admission follows the runtime clock while old evidence pages keep their original identity.

use std::cell::Cell;

use super::*;
use fss_reference::deployment_session::{SessionContext, SessionTimeAuthority, SessionTimeError};

const START: i128 = 1_700_000_000_000_000_000;

struct Clock(Cell<i128>);

impl SessionTimeAuthority for Clock {
    fn observe(&self, _: &Path, _: &PrincipalId) -> Result<TimestampNs, SessionTimeError> {
        Ok(TimestampNs(self.0.get()))
    }
}

fn runtime_fixture(tag: &str, clock: &Clock) -> TestResult<Fixture> {
    let mut fixture = Fixture::new(tag)?;
    fixture.opened = open_session(
        SessionContext::runtime(&fixture.root, clock),
        &OpenSessionRequest {
            mission: "Observe every retained transition with live lease admission".into(),
            objective: "Replay historical evidence without regressing the session clock".into(),
            principal: fixture.opened.session.principal_id.clone(),
            view: AgentView::Brief,
            token_budget: 100_000,
        },
    )?;
    assert_eq!(fixture.opened.session.created_at_ns, START);
    fixture.append()?;
    Ok(fixture)
}

#[test]
fn runtime_follow_replays_historical_pages_without_reverting_its_clock() -> TestResult {
    let clock = Clock(Cell::new(START));
    let fixture = runtime_fixture("runtime-follow", &clock)?;
    let request = fixture.request(8)?;
    clock.0.set(START + 100);
    let first = follow_session(
        SessionContext::runtime(&fixture.root, &clock),
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut Control::new(&fixture.root, &request, &fixture.opened),
    )?;
    assert!(!first.replayed);
    clock.0.set(START + 200);
    let replayed = follow_session(
        SessionContext::runtime(&fixture.root, &clock),
        &fixture.opened.session.principal_id,
        &request,
        &OrientLimits::default(),
        &mut Control::new(&fixture.root, &request, &fixture.opened),
    )?;
    assert!(replayed.replayed);
    assert_eq!(replayed.delivery_receipt, first.delivery_receipt);
    assert_eq!(replayed.since_anchor, first.since_anchor);
    assert_eq!(replayed.result_anchor, first.result_anchor);
    let retained = fixture.inspect()?;
    let retained = retained
        .sessions
        .iter()
        .find(|entry| entry.session.session_id == fixture.opened.session.session_id)
        .ok_or("runtime follow session")?;
    assert_eq!(retained.last_observed_at, TimestampNs(START + 200));
    assert_eq!(retained.session.created_at_ns, START);
    assert!(!retained.closed);
    Ok(())
}

#[test]
fn expiry_during_follow_revalidation_is_durable_and_withholds_the_page() -> TestResult {
    let clock = Clock(Cell::new(START));
    let fixture = runtime_fixture("runtime-follow-expiry", &clock)?;
    let request = fixture.request(8)?;
    let expiry = fixture.opened.session.expires_at_ns;
    let mut control = Control::new(&fixture.root, &request, &fixture.opened);
    control.before_revalidate = Some(Box::new(|| {
        clock.0.set(expiry);
        Ok(())
    }));
    assert!(
        follow_session(
            SessionContext::runtime(&fixture.root, &clock),
            &fixture.opened.session.principal_id,
            &request,
            &OrientLimits::default(),
            &mut control,
        )
        .is_err()
    );
    let retained = fixture.inspect()?;
    assert!(
        retained
            .sessions
            .iter()
            .any(
                |entry| entry.session.session_id == fixture.opened.session.session_id
                    && entry.closed
            )
    );
    assert!(
        retained
            .follows
            .iter()
            .all(|subscription| subscription.pending().is_none())
    );
    clock.0.set(START);
    assert!(
        follow_session(
            SessionContext::runtime(&fixture.root, &clock),
            &fixture.opened.session.principal_id,
            &request,
            &OrientLimits::default(),
            &mut Control::new(&fixture.root, &request, &fixture.opened),
        )
        .is_err()
    );
    Ok(())
}
