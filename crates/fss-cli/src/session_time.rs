#![forbid(unsafe_code)]
//! Local transport-owned session clock. Agent requests cannot choose current time.

use std::cell::Cell;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fss_core::{PrincipalId, TimestampNs};
use fss_reference::deployment_session::{SessionContext, SessionTimeAuthority, SessionTimeError};

pub(crate) type Clock<'a> = Option<&'a dyn SessionTimeAuthority>;

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
    use std::time::Duration;

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
}
