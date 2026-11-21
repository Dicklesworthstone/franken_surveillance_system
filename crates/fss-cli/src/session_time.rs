#![forbid(unsafe_code)]
//! Local transport-owned session clock. Agent requests cannot choose current time.

use std::cell::Cell;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fss_core::{PrincipalId, TimestampNs};
use fss_reference::deployment_session::{SessionContext, SessionTimeAuthority, SessionTimeError};

pub(crate) type Clock<'a> = Option<&'a dyn SessionTimeAuthority>;

/// Add the request owner's existing cancellation to the native session clock boundary.
/// Started effects deliberately keep their original clock and durable execution owner.
pub(crate) struct ControlledSessionTime<'a, 'request> {
    pub(crate) clock: &'a dyn SessionTimeAuthority,
    pub(crate) control: &'a crate::RequestControl<'request>,
}

impl SessionTimeAuthority for ControlledSessionTime<'_, '_> {
    fn observe(
        &self,
        root: &Path,
        principal: &PrincipalId,
    ) -> Result<TimestampNs, SessionTimeError> {
        if self.control.is_cancelled() {
            return Err(SessionTimeError::Cancelled);
        }
        self.clock.observe(root, principal)
    }
}

pub(crate) fn context<'a>(root: &'a Path, clock: Clock<'a>) -> SessionContext<'a> {
    match clock {
        Some(clock) => SessionContext::runtime(root, clock),
        None => SessionContext::evidence(root),
    }
}

/// Clock owned by one local CLI/MCP command, under its existing OS-account/root scope.
/// This capability only supplies time; it grants no session, source or effect authority.
/// Every observation reads the host clock anew. The durable session owner also rejects
/// regression across commands and restarts, preserving expiry and cumulative budget state.
#[derive(Default)]
pub struct HostSessionTime {
    previous: Cell<Option<i128>>,
}

impl HostSessionTime {
    fn observe_sample(&self, sample: SystemTime) -> Result<TimestampNs, SessionTimeError> {
        let elapsed = sample
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SessionTimeError::Uncertain)?;
        let now = i128::try_from(elapsed.as_nanos()).map_err(|_| SessionTimeError::Uncertain)?;
        if self.previous.get().is_some_and(|previous| now < previous) {
            return Err(SessionTimeError::Uncertain);
        }
        self.previous.set(Some(now));
        Ok(TimestampNs(now))
    }
}

impl SessionTimeAuthority for HostSessionTime {
    fn observe(
        &self,
        root: &Path,
        principal: &PrincipalId,
    ) -> Result<TimestampNs, SessionTimeError> {
        if root.as_os_str().is_empty() || principal.as_str().is_empty() {
            return Err(SessionTimeError::Denied);
        }
        self.observe_sample(SystemTime::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn request_cancellation_stops_the_original_clock_before_another_observation()
    -> Result<(), Box<dyn std::error::Error>> {
        struct Clock(Cell<u32>);
        impl SessionTimeAuthority for Clock {
            fn observe(&self, _: &Path, _: &PrincipalId) -> Result<TimestampNs, SessionTimeError> {
                self.0.set(self.0.get() + 1);
                Ok(TimestampNs(123))
            }
        }
        let original = Clock(Cell::new(0));
        let cancelled = AtomicBool::new(false);
        let probe = || cancelled.load(Ordering::Acquire);
        let control = crate::RequestControl::new(&probe);
        let clock = ControlledSessionTime {
            clock: &original,
            control: &control,
        };
        let principal = PrincipalId::parse("principal:request-clock")?;
        let root = Path::new("/request-clock");
        assert_eq!(clock.observe(root, &principal), Ok(TimestampNs(123)));
        cancelled.store(true, Ordering::Release);
        assert_eq!(
            clock.observe(root, &principal),
            Err(SessionTimeError::Cancelled)
        );
        assert_eq!(
            original.0.get(),
            1,
            "no clock observation after cancellation"
        );
        // A started effect deliberately retains this original capability, not the wrapper.
        assert_eq!(original.observe(root, &principal), Ok(TimestampNs(123)));
        assert_eq!(original.0.get(), 2);
        Ok(())
    }

    #[test]
    fn host_clock_uses_nanoseconds_and_refuses_regression_without_resetting_its_watermark() {
        let clock = HostSessionTime::default();
        let first = UNIX_EPOCH + Duration::new(1_800_000_000, 123);
        assert_eq!(
            clock.observe_sample(first),
            Ok(TimestampNs(1_800_000_000_000_000_123))
        );
        assert_eq!(
            clock.observe_sample(first - Duration::from_nanos(1)),
            Err(SessionTimeError::Uncertain)
        );
        assert_eq!(
            clock.observe_sample(first),
            Ok(TimestampNs(1_800_000_000_000_000_123))
        );
        assert_eq!(
            clock.observe_sample(first + Duration::from_nanos(1)),
            Ok(TimestampNs(1_800_000_000_000_000_124))
        );
    }

    #[test]
    fn pre_epoch_host_time_is_uncertain_and_does_not_establish_a_clock() {
        let clock = HostSessionTime::default();
        assert_eq!(
            clock.observe_sample(UNIX_EPOCH - Duration::from_nanos(1)),
            Err(SessionTimeError::Uncertain)
        );
        assert_eq!(clock.previous.get(), None);
        assert_eq!(clock.observe_sample(UNIX_EPOCH), Ok(TimestampNs(0)));
    }

    #[test]
    fn cancelled_host_observation_does_not_establish_or_advance_its_watermark()
    -> Result<(), Box<dyn std::error::Error>> {
        let host = HostSessionTime::default();
        let control = crate::RequestControl::new(&|| true);
        let clock = ControlledSessionTime {
            clock: &host,
            control: &control,
        };
        let principal = PrincipalId::parse("principal:cancelled-clock")?;
        let root = Path::new("/owned-session-root");
        assert_eq!(
            clock.observe(root, &principal),
            Err(SessionTimeError::Cancelled)
        );
        assert_eq!(host.previous.get(), None);
        assert_eq!(
            host.observe_sample(UNIX_EPOCH + Duration::from_nanos(42)),
            Ok(TimestampNs(42))
        );
        assert_eq!(
            clock.observe(root, &principal),
            Err(SessionTimeError::Cancelled)
        );
        assert_eq!(host.previous.get(), Some(42));
        Ok(())
    }
}
