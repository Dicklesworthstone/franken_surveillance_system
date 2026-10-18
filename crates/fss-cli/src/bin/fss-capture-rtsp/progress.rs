#![forbid(unsafe_code)]
//! Owner-clock recording progress and elapsed-duration boundaries, not sensor health.
//! Storage backpressure pauses the progress allowance, but NOT a capture-duration limit
//! or the independent native deadlines. A stop observation is never an archive receipt.

use fss_cli::agent_json::{object, string};
use fss_core::{ContentDigest, DigestAlgorithm};

/// Extra policy is delegated only by the exact approved reconnect plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Supervision {
    timeout_ns: Option<u64>,
    duration_ns: Option<u64>,
    approval: ContentDigest,
}
impl Supervision {
    pub(crate) const POLICY: &str = "recording-progress:arm-on-playing:renew-on-collected-picture:\
exclude-storage-pause:expiry-before-late-progress:seal-and-drain-before-retry:\
not-camera-offline:not-eof:not-coverage:v1";
    pub(crate) const TIMED_POLICY: &str = "recording-stop:arm-on-playing:\
duration-includes-storage-pause:progress-excludes-storage-pause:\
earliest-boundary-wins:progress-wins-ties:expiry-before-late-progress:\
seal-and-drain-before-completion:not-camera-time:not-eof:not-coverage:v1";

    pub(crate) fn new(timeout_ns: u64, approval: ContentDigest) -> Result<Self, &'static str> {
        Self::with_limits(Some(timeout_ns), None, approval)
    }

    pub(crate) fn with_limits(
        timeout_ns: Option<u64>,
        duration_ns: Option<u64>,
        approval: ContentDigest,
    ) -> Result<Self, &'static str> {
        if (timeout_ns.is_none() && duration_ns.is_none())
            || [timeout_ns, duration_ns]
                .into_iter()
                .flatten()
                .any(|limit| !(1..=600_000_000_000).contains(&limit))
            || approval.algorithm() != DigestAlgorithm::Sha256
            || approval.bytes() == [0; 32]
        {
            return Err("ERR-CAPTURE-RTSP-CONFIG-001");
        }
        Ok(Self {
            timeout_ns,
            duration_ns,
            approval,
        })
    }

    fn policy(self) -> &'static str {
        if self.duration_ns.is_some() {
            Self::TIMED_POLICY
        } else {
            Self::POLICY
        }
    }

    pub(super) fn report(self) -> String {
        let mut fields = vec![
            ("approval", string(&self.approval.to_text())),
            ("policy", string(self.policy())),
            (
                "progress_timeout_ns",
                self.timeout_ns
                    .map_or_else(|| "null".into(), |n| n.to_string()),
            ),
            ("camera_offline_asserted", "false".into()),
            ("pixel_decode_asserted", "false".into()),
        ];
        if let Some(duration) = self.duration_ns {
            fields.push(("capture_duration_ns", duration.to_string()));
            fields.push(("duration_includes_storage_pause", "true".into()));
            fields.push(("camera_time_asserted", "false".into()));
        }
        object(&fields)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WatchError {
    ClockReversed,
    CountReversed,
    Arithmetic,
}

/// A planned duration boundary is distinct from an absence of collected pictures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StopCause {
    ProgressStalled,
    CaptureDuration,
}

/// Latched before accepting a late counter advance. Repeated polls cannot erase it.
/// The historical type name is retained for existing single-timeout callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Stall {
    pub(super) cause: StopCause,
    observed_ns: u64,
    last_progress_ns: Option<u64>,
    pictures_before_expiry: u64,
    active_wait_ns: u64,
    paused_ns: u64,
    capture_elapsed_ns: u64,
}
impl Stall {
    pub(super) fn report(self, policy: Supervision) -> String {
        let mut fields = vec![
            ("approval", string(&policy.approval.to_text())),
            ("policy", string(policy.policy())),
            (
                "progress_timeout_ns",
                policy
                    .timeout_ns
                    .map_or_else(|| "null".into(), |n| n.to_string()),
            ),
            ("observed_owner_ns", self.observed_ns.to_string()),
            (
                "last_progress_owner_ns",
                self.last_progress_ns
                    .map_or_else(|| "null".into(), |n| n.to_string()),
            ),
            (
                "pictures_before_expiry",
                self.pictures_before_expiry.to_string(),
            ),
            ("active_wait_ns", self.active_wait_ns.to_string()),
            ("excluded_pause_ns", self.paused_ns.to_string()),
            ("source_eof_asserted", "false".into()),
            ("camera_offline_asserted", "false".into()),
            ("absence_certifiable", "false".into()),
            ("archive_drained", "false".into()),
        ];
        if let Some(duration) = policy.duration_ns {
            fields.push(("capture_duration_ns", duration.to_string()));
            fields.push(("capture_elapsed_ns", self.capture_elapsed_ns.to_string()));
            fields.push((
                "stop_cause",
                string(match self.cause {
                    StopCause::ProgressStalled => "recording_progress_stalled",
                    StopCause::CaptureDuration => "capture_duration_elapsed",
                }),
            ));
            fields.push(("duration_includes_storage_pause", "true".into()));
            fields.push(("camera_time_asserted", "false".into()));
        }
        object(&fields)
    }
}

/// Constant-space observer of one attempt. The driver samples before each capture
/// step and after its output, so a storage transition preserves elapsed active time.
/// Only the native collector's increasing picture count renews the progress allowance;
/// neither picture traffic nor storage pauses renew the elapsed-duration allowance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RecordingProgress {
    policy: Option<Supervision>,
    last_ns: Option<u64>,
    last_progress_ns: Option<u64>,
    pictures: u64,
    armed: bool,
    active: bool,
    waited_ns: u64,
    paused_ns: u64,
    capture_elapsed_ns: u64,
    expired: Option<Stall>,
}
impl RecordingProgress {
    pub(super) fn new(policy: Option<Supervision>) -> Self {
        Self {
            policy,
            last_ns: None,
            last_progress_ns: None,
            pictures: 0,
            armed: false,
            active: false,
            waited_ns: 0,
            paused_ns: 0,
            capture_elapsed_ns: 0,
            expired: None,
        }
    }

    /// Account for a measured synchronous storage interval between driver polls.
    /// Earlier progress expiry stays latched; duration still advances while paused.
    /// Reject invalid clock/counter input without partially changing the observer.
    pub(super) fn exclude_storage_interval(
        &mut self,
        start: u64,
        end: u64,
        playing: bool,
        enabled: bool,
        pictures: u64,
    ) -> Result<(), WatchError> {
        if end < start {
            return Err(WatchError::ClockReversed);
        }
        let mut next = self.clone();
        next.observe(start, playing, false, pictures)?;
        next.observe(end, playing, enabled, pictures)?;
        *self = next;
        Ok(())
    }

    pub(super) fn observe(
        &mut self,
        now: u64,
        playing: bool,
        enabled: bool,
        pictures: u64,
    ) -> Result<Option<Stall>, WatchError> {
        let Some(policy) = self.policy else {
            return Ok(None);
        };
        let elapsed = match self.last_ns {
            Some(previous) => now.checked_sub(previous).ok_or(WatchError::ClockReversed)?,
            None => 0,
        };
        if pictures < self.pictures {
            return Err(WatchError::CountReversed);
        }
        // Validate arithmetic before mutating any state, including after an error retry.
        let waited = if self.active && self.expired.is_none() {
            self.waited_ns
                .checked_add(elapsed)
                .ok_or(WatchError::Arithmetic)?
        } else {
            self.waited_ns
        };
        let paused = if self.armed && !self.active && self.expired.is_none() {
            self.paused_ns
                .checked_add(elapsed)
                .ok_or(WatchError::Arithmetic)?
        } else {
            self.paused_ns
        };
        let capture_elapsed = if self.armed && self.expired.is_none() {
            self.capture_elapsed_ns
                .checked_add(elapsed)
                .ok_or(WatchError::Arithmetic)?
        } else {
            self.capture_elapsed_ns
        };
        // Compare the remaining allowances BEFORE applying this sample. When a delayed
        // observation crosses both boundaries, a later planned stop must not disguise an
        // earlier progress failure as success. Progress also wins an exact tie.
        let progress_due = policy
            .timeout_ns
            .filter(|_| self.active)
            .map(|limit| limit.saturating_sub(self.waited_ns))
            .filter(|remaining| *remaining <= elapsed);
        let duration_due = policy
            .duration_ns
            .filter(|_| self.armed)
            .map(|limit| limit.saturating_sub(self.capture_elapsed_ns))
            .filter(|remaining| *remaining <= elapsed);
        let cause = match (progress_due, duration_due) {
            (Some(progress), Some(duration)) if duration < progress => {
                Some(StopCause::CaptureDuration)
            }
            (Some(_), _) => Some(StopCause::ProgressStalled),
            (None, Some(_)) => Some(StopCause::CaptureDuration),
            (None, None) => None,
        };
        self.last_ns = Some(now);
        self.waited_ns = waited;
        self.paused_ns = paused;
        self.capture_elapsed_ns = capture_elapsed;
        self.armed |= playing;
        if self.expired.is_none()
            && let Some(cause) = cause
        {
            self.expired = Some(Stall {
                cause,
                observed_ns: now,
                last_progress_ns: self.last_progress_ns,
                pictures_before_expiry: self.pictures,
                active_wait_ns: self.waited_ns,
                paused_ns: self.paused_ns,
                capture_elapsed_ns: self.capture_elapsed_ns,
            });
        }
        if pictures > self.pictures && self.expired.is_none() {
            self.waited_ns = 0;
            self.last_progress_ns = Some(now);
        }
        self.pictures = pictures;
        self.active = self.armed && playing && enabled;
        Ok(self.expired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch() -> RecordingProgress {
        RecordingProgress::new(Some(
            Supervision::new(100, ContentDigest::sha256(b"approved supervision"))
                .expect("valid policy"),
        ))
    }

    fn timed(progress: Option<u64>, duration: u64) -> RecordingProgress {
        RecordingProgress::new(Some(
            Supervision::with_limits(
                progress,
                Some(duration),
                ContentDigest::sha256(b"approved timed capture"),
            )
            .expect("valid timed policy"),
        ))
    }

    #[test]
    fn invalid_policy_is_refused_before_any_owner_effect() {
        let approval = ContentDigest::sha256(b"approval");
        for limit in [0, 600_000_000_001, u64::MAX] {
            assert!(Supervision::new(limit, approval).is_err());
            assert!(Supervision::with_limits(None, Some(limit), approval).is_err());
            assert!(Supervision::with_limits(Some(100), Some(limit), approval).is_err());
        }
        assert!(Supervision::with_limits(None, None, approval).is_err());
        assert!(Supervision::with_limits(None, Some(1), approval).is_ok());
        assert!(Supervision::with_limits(None, Some(600_000_000_000), approval).is_ok());
        assert!(Supervision::new(1, approval).is_ok());
        assert!(Supervision::new(600_000_000_000, approval).is_ok());
        let zero =
            ContentDigest::parse(&format!("sha256:{}", "0".repeat(64))).expect("digest syntax");
        assert!(Supervision::new(100, zero).is_err());
        assert!(Supervision::with_limits(None, Some(100), zero).is_err());
    }

    #[test]
    fn connection_and_setup_time_do_not_consume_recording_startup_allowance() {
        let mut w = watch();
        assert_eq!(w.observe(0, false, true, 0), Ok(None));
        assert_eq!(w.observe(10_000, false, true, 0), Ok(None));
        assert_eq!(w.observe(20_000, true, true, 0), Ok(None));
        assert_eq!(w.observe(20_099, true, true, 0), Ok(None));
        let r = w
            .observe(20_100, true, true, 0)
            .expect("clock")
            .expect("expiry");
        assert_eq!(r.cause, StopCause::ProgressStalled);
        assert_eq!(r.active_wait_ns, 100);
        assert_eq!(r.last_progress_ns, None);
        assert_eq!(r.pictures_before_expiry, 0);
    }

    #[test]
    fn increasing_collected_count_renews_but_noise_and_duplicates_do_not() {
        let mut w = watch();
        assert_eq!(w.observe(0, true, true, 0), Ok(None));
        assert_eq!(w.observe(90, true, true, 1), Ok(None));
        for now in 91..190 {
            assert_eq!(w.observe(now, true, true, 1), Ok(None));
        }
        let r = w
            .observe(190, true, true, 1)
            .expect("clock")
            .expect("expiry");
        assert_eq!(r.last_progress_ns, Some(90));
        assert_eq!(r.pictures_before_expiry, 1);
        assert_eq!(r.active_wait_ns, 100);
    }

    #[test]
    fn storage_pause_preserves_remaining_allowance_without_refilling_it() {
        let mut w = watch();
        assert_eq!(w.observe(0, true, true, 0), Ok(None));
        assert_eq!(w.observe(40, true, false, 0), Ok(None));
        assert_eq!(w.observe(1000, true, false, 0), Ok(None));
        assert_eq!(w.observe(2000, true, true, 0), Ok(None));
        assert_eq!(w.observe(2059, true, true, 0), Ok(None));
        let r = w
            .observe(2060, true, true, 0)
            .expect("clock")
            .expect("expiry");
        assert_eq!(r.active_wait_ns, 100);
        assert_eq!(r.paused_ns, 1960);
    }

    #[test]
    fn exact_deadline_and_late_progress_cannot_resurrect_expired_attempt() {
        for arrival in [100, 101, u64::MAX] {
            let mut w = watch();
            assert_eq!(w.observe(0, true, true, 0), Ok(None));
            let receipt = w
                .observe(arrival, true, true, 1)
                .expect("clock")
                .expect("late progress must not erase expiry");
            assert_eq!(receipt.pictures_before_expiry, 0);
            assert_eq!(receipt.last_progress_ns, None);
            assert_eq!(w.observe(arrival, true, false, 2), Ok(Some(receipt)));
            assert_eq!(w.observe(arrival, true, true, 3), Ok(Some(receipt)));
        }
    }

    #[test]
    fn clock_and_counter_refusals_preserve_all_prior_timer_state() {
        let mut w = watch();
        assert_eq!(w.observe(10, true, true, 1), Ok(None));
        assert_eq!(w.observe(50, true, true, 1), Ok(None));
        let before = w.clone();
        assert_eq!(w.observe(49, true, true, 2), Err(WatchError::ClockReversed));
        assert_eq!(w, before);
        assert_eq!(w.observe(80, true, true, 0), Err(WatchError::CountReversed));
        assert_eq!(w, before);
        assert_eq!(w.observe(109, true, true, 1), Ok(None));
        assert!(w.observe(110, true, true, 1).expect("clock").is_some());
    }

    #[test]
    fn maximum_owner_timestamp_never_wraps_a_deadline() {
        let mut w = watch();
        assert_eq!(w.observe(u64::MAX - 100, true, true, 0), Ok(None));
        assert_eq!(w.observe(u64::MAX - 1, true, true, 0), Ok(None));
        let r = w
            .observe(u64::MAX, true, true, 0)
            .expect("clock")
            .expect("expiry");
        assert_eq!(r.active_wait_ns, 100);
    }

    #[test]
    fn a_new_attempt_does_not_inherit_progress_or_expiry() {
        let mut old = watch();
        assert_eq!(old.observe(0, true, true, 4), Ok(None));
        assert!(old.observe(100, true, true, 4).expect("clock").is_some());
        let mut new = watch();
        assert_eq!(new.observe(500, true, true, 0), Ok(None));
        assert_eq!(new.observe(599, true, true, 1), Ok(None));
        assert_eq!(new.observe(698, true, true, 1), Ok(None));
        assert!(new.observe(699, true, true, 1).expect("clock").is_some());
    }

    #[test]
    fn disabled_observer_is_inert_and_does_not_add_legacy_refusals() {
        let mut w = RecordingProgress::new(None);
        let before = w.clone();
        assert_eq!(w.observe(u64::MAX, true, true, u64::MAX), Ok(None));
        assert_eq!(w.observe(0, true, true, 0), Ok(None));
        assert_eq!(w, before);
    }

    #[test]
    fn duration_arms_at_play_and_is_not_renewed_by_collected_pictures() {
        let mut w = timed(None, 100);
        assert_eq!(w.observe(0, false, true, 0), Ok(None));
        assert_eq!(w.observe(10_000, false, true, 0), Ok(None));
        assert_eq!(w.observe(20_000, true, true, 0), Ok(None));
        for i in 1..100 {
            assert_eq!(w.observe(20_000 + i, true, true, i), Ok(None));
        }
        let r = w.observe(20_100, true, true, 100).unwrap().unwrap();
        assert_eq!(r.cause, StopCause::CaptureDuration);
        assert_eq!(r.capture_elapsed_ns, 100);
        assert_eq!(r.pictures_before_expiry, 99);
        assert_eq!(r.last_progress_ns, Some(20_099));
        assert_eq!(w.observe(30_000, true, false, 101), Ok(Some(r)));
    }

    #[test]
    fn duration_includes_storage_pause_without_spending_progress_allowance() {
        let mut w = timed(Some(100), 200);
        assert_eq!(w.observe(0, true, true, 0), Ok(None));
        assert_eq!(w.observe(40, true, false, 1), Ok(None));
        assert_eq!(w.observe(199, true, false, 1), Ok(None));
        let r = w.observe(200, true, false, 1).unwrap().unwrap();
        assert_eq!(r.cause, StopCause::CaptureDuration);
        assert_eq!(r.capture_elapsed_ns, 200);
        assert_eq!(r.active_wait_ns, 0);
        assert_eq!(r.paused_ns, 160);
    }

    #[test]
    fn late_observation_chooses_the_first_boundary_and_progress_wins_ties() {
        for (progress, duration, cause) in [
            (50, 100, StopCause::ProgressStalled),
            (100, 50, StopCause::CaptureDuration),
            (100, 100, StopCause::ProgressStalled),
        ] {
            let mut w = timed(Some(progress), duration);
            assert_eq!(w.observe(0, true, true, 1), Ok(None));
            let r = w.observe(200, true, true, 2).unwrap().unwrap();
            assert_eq!(r.cause, cause);
            assert_eq!(r.pictures_before_expiry, 1);
        }
    }

    #[test]
    fn picture_renewal_changes_progress_deadline_but_not_capture_boundary() {
        let mut w = timed(Some(100), 150);
        assert_eq!(w.observe(0, true, true, 0), Ok(None));
        assert_eq!(w.observe(90, true, true, 1), Ok(None));
        let r = w.observe(200, true, true, 2).unwrap().unwrap();
        assert_eq!(r.cause, StopCause::CaptureDuration);
        assert_eq!(r.last_progress_ns, Some(90));
    }

    #[test]
    fn paused_progress_is_not_misclassified_as_an_earlier_failure() {
        let mut w = timed(Some(50), 100);
        assert_eq!(w.observe(0, true, true, 0), Ok(None));
        assert_eq!(w.observe(40, true, false, 0), Ok(None));
        let r = w.observe(200, true, true, 0).unwrap().unwrap();
        assert_eq!(r.cause, StopCause::CaptureDuration);
        assert_eq!(r.active_wait_ns, 40);
    }

    #[test]
    fn timed_refusals_are_transactional_and_new_attempts_start_fresh() {
        let mut w = timed(None, 100);
        assert_eq!(w.observe(10, true, true, 1), Ok(None));
        assert_eq!(w.observe(50, true, false, 1), Ok(None));
        let before = w.clone();
        assert_eq!(w.observe(49, true, true, 2), Err(WatchError::ClockReversed));
        assert_eq!(w, before);
        assert_eq!(w.observe(60, true, true, 0), Err(WatchError::CountReversed));
        assert_eq!(w, before);
        assert_eq!(w.observe(109, true, false, 1), Ok(None));
        assert!(w.observe(110, true, false, 1).unwrap().is_some());
        let mut fresh = timed(None, 100);
        assert_eq!(fresh.observe(110, true, true, 0), Ok(None));
        assert_eq!(fresh.observe(209, true, true, 0), Ok(None));
        assert!(fresh.observe(210, true, true, 0).unwrap().is_some());
    }

    #[test]
    fn duration_expiry_at_maximum_timestamp_does_not_wrap() {
        let mut w = timed(None, 100);
        assert_eq!(w.observe(u64::MAX - 100, true, true, 0), Ok(None));
        assert_eq!(w.observe(u64::MAX - 1, true, true, 0), Ok(None));
        let r = w.observe(u64::MAX, true, true, 1).unwrap().unwrap();
        assert_eq!(r.cause, StopCause::CaptureDuration);
        assert_eq!(r.capture_elapsed_ns, 100);
        assert_eq!(r.pictures_before_expiry, 0);
    }

    #[test]
    fn timed_reports_do_not_turn_a_timer_observation_into_source_or_archive_proof() {
        let mut w = timed(None, 100);
        w.observe(0, true, true, 1).unwrap();
        let stop = w.observe(100, true, true, 1).unwrap().unwrap();
        let report = stop.report(w.policy.unwrap());
        for expected in [
            "\"stop_cause\":\"capture_duration_elapsed\"",
            "\"progress_timeout_ns\":null",
            "\"capture_duration_ns\":100",
            "\"duration_includes_storage_pause\":true",
            "\"source_eof_asserted\":false",
            "\"camera_time_asserted\":false",
            "\"absence_certifiable\":false",
            "\"archive_drained\":false",
        ] {
            assert!(report.contains(expected), "missing {expected}: {report}");
        }
    }
}

#[cfg(test)]
mod source_storage_tests {
    use super::*;
    fn observer(duration: u64, progress: u64) -> Result<RecordingProgress, &'static str> {
        let policy = Supervision::with_limits(
            Some(progress),
            Some(duration),
            ContentDigest::sha256(b"source policy"),
        )?;
        let mut observer = RecordingProgress::new(Some(policy));
        observer
            .observe(0, true, true, 0)
            .map_err(|_| "initial observation")?;
        Ok(observer)
    }
    #[test]
    fn source_publication_pauses_only_the_progress_clock() -> Result<(), &'static str> {
        let mut watch = observer(200, 20)?;
        watch
            .exclude_storage_interval(10, 100, true, true, 0)
            .map_err(|_| "source interval")?;
        assert_eq!(watch.waited_ns, 10);
        assert_eq!(watch.paused_ns, 90);
        assert_eq!(watch.capture_elapsed_ns, 100);
        assert_eq!(
            watch
                .observe(109, true, true, 0)
                .map_err(|_| "observation")?,
            None
        );
        let stop = watch
            .observe(110, true, true, 0)
            .map_err(|_| "observation")?
            .ok_or("missing stop")?;
        assert_eq!(stop.cause, StopCause::ProgressStalled);
        assert_eq!(stop.active_wait_ns, 20);
        assert_eq!(stop.paused_ns, 90);
        Ok(())
    }
    #[test]
    fn duration_expiring_during_source_publication_is_not_extended() -> Result<(), &'static str> {
        let mut watch = observer(50, 20)?;
        watch
            .exclude_storage_interval(10, 100, true, true, 0)
            .map_err(|_| "source interval")?;
        let stop = watch.expired.ok_or("missing duration")?;
        assert_eq!(stop.cause, StopCause::CaptureDuration);
        assert_eq!(stop.capture_elapsed_ns, 100);
        assert_eq!(stop.active_wait_ns, 10);
        Ok(())
    }
    #[test]
    fn earlier_progress_failure_cannot_hide_behind_source_storage_or_late_picture()
    -> Result<(), &'static str> {
        let mut watch = observer(50, 8)?;
        watch
            .exclude_storage_interval(10, 100, true, true, 1)
            .map_err(|_| "source interval")?;
        let stop = watch.expired.ok_or("missing progress stop")?;
        assert_eq!(stop.cause, StopCause::ProgressStalled);
        assert_eq!(stop.pictures_before_expiry, 0);
        assert_eq!(stop.observed_ns, 10);
        Ok(())
    }
    #[test]
    fn invalid_source_interval_is_transactionally_refused() -> Result<(), &'static str> {
        let mut watch = observer(50, 20)?;
        watch.observe(5, true, true, 1).map_err(|_| "observation")?;
        let before = watch.clone();
        for (start, end, pictures) in [(4, 10, 1), (10, 9, 1), (10, 20, 0)] {
            assert!(
                watch
                    .exclude_storage_interval(start, end, true, true, pictures)
                    .is_err()
            );
            assert_eq!(watch, before);
        }
        Ok(())
    }
}
