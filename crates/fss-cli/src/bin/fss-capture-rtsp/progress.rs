#![forbid(unsafe_code)]
//! Owner-clock recording progress, not transport keepalive or physical sensor health.
//! Storage backpressure pauses this allowance, never the independent native deadlines.

use fss_cli::agent_json::{object, string};
use fss_core::{ContentDigest, DigestAlgorithm};

/// Extra policy is delegated only by the exact approved reconnect plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Supervision {
    timeout_ns: u64,
    approval: ContentDigest,
}
impl Supervision {
    pub(crate) const POLICY: &str = "recording-progress:arm-on-playing:renew-on-collected-picture:\
exclude-storage-pause:expiry-before-late-progress:seal-and-drain-before-retry:\
not-camera-offline:not-eof:not-coverage:v1";

    pub(crate) fn new(timeout_ns: u64, approval: ContentDigest) -> Result<Self, &'static str> {
        if !(1..=600_000_000_000).contains(&timeout_ns)
            || approval.algorithm() != DigestAlgorithm::Sha256
            || approval.bytes() == [0; 32]
        {
            return Err("ERR-CAPTURE-RTSP-CONFIG-001");
        }
        Ok(Self {
            timeout_ns,
            approval,
        })
    }

    pub(super) fn report(self) -> String {
        object(&[
            ("approval", string(&self.approval.to_text())),
            ("policy", string(Self::POLICY)),
            ("progress_timeout_ns", self.timeout_ns.to_string()),
            ("camera_offline_asserted", "false".into()),
            ("pixel_decode_asserted", "false".into()),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WatchError {
    ClockReversed,
    CountReversed,
    Arithmetic,
}

/// Latched before accepting a late counter advance. Repeated polls cannot erase it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Stall {
    observed_ns: u64,
    last_progress_ns: Option<u64>,
    pictures_before_expiry: u64,
    active_wait_ns: u64,
    paused_ns: u64,
}
impl Stall {
    pub(super) fn report(self, policy: Supervision) -> String {
        object(&[
            ("approval", string(&policy.approval.to_text())),
            ("policy", string(Supervision::POLICY)),
            ("progress_timeout_ns", policy.timeout_ns.to_string()),
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
        ])
    }
}

/// Constant-space observer of one attempt. The driver samples before each capture
/// step and after its output, so a storage transition preserves elapsed active time.
/// Only the native collector's increasing picture count renews the allowance.
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
            expired: None,
        }
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
        self.last_ns = Some(now);
        self.waited_ns = waited;
        self.paused_ns = paused;
        self.armed |= playing;
        if self.armed && self.waited_ns >= policy.timeout_ns && self.expired.is_none() {
            self.expired = Some(Stall {
                observed_ns: now,
                last_progress_ns: self.last_progress_ns,
                pictures_before_expiry: self.pictures,
                active_wait_ns: self.waited_ns,
                paused_ns: self.paused_ns,
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

    #[test]
    fn invalid_policy_is_refused_before_any_owner_effect() {
        let approval = ContentDigest::sha256(b"approval");
        for limit in [0, 600_000_000_001, u64::MAX] {
            assert!(Supervision::new(limit, approval).is_err());
        }
        assert!(Supervision::new(1, approval).is_ok());
        assert!(Supervision::new(600_000_000_000, approval).is_ok());
        let zero =
            ContentDigest::parse(&format!("sha256:{}", "0".repeat(64))).expect("digest syntax");
        assert!(Supervision::new(100, zero).is_err());
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
}
