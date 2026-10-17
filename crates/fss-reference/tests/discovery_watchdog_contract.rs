//! Contract tests for the device-liveness watchdog (DISC-5, fss-niak9):
//! the dark-camera honesty rules — silence is a typed state, never "clear";
//! battery cams sleep without going "offline"; recovery transitions are
//! recorded; never-observed devices never churn duplicate records.

use fss_reference::discovery::watchdog::{
    DeviceClass, DeviceWatchdog, WatchOfflineReason, WatchState,
};

const MIN: u64 = 60_000_000_000;
const HOUR: u64 = 60 * MIN;

#[test]
fn never_observed_is_not_observable_not_clear() {
    let mut w = DeviceWatchdog::new();
    w.register("cam-1", DeviceClass::Tutk, None);
    assert_eq!(
        w.state_of("cam-1"),
        Some(&WatchState::NotObservable {
            reason: WatchOfflineReason::NeverObserved
        })
    );
    // And evaluating with no sightings produces NO records (no churn).
    w.evaluate(10 * MIN);
    assert!(w.changes().is_empty(), "never-observed must not churn");
}

#[test]
fn sighting_makes_observable_and_records_the_transition() {
    let mut w = DeviceWatchdog::new();
    w.register("cam-1", DeviceClass::Tutk, None);
    w.observe("cam-1", 1_000);
    assert_eq!(w.state_of("cam-1"), Some(&WatchState::Observable));
    let changes = w.changes();
    assert_eq!(changes.len(), 1);
    assert_eq!(
        changes[0].from,
        WatchState::NotObservable {
            reason: WatchOfflineReason::NeverObserved
        }
    );
    assert_eq!(changes[0].to, WatchState::Observable);
    // Canonical record text is deterministic.
    assert_eq!(
        changes[0].to_record(),
        "{\"type\":\"device_state_change\",\"device\":\"cam-1\",\"class\":\"tutk\",\"from\":\"not_observable\",\"to\":\"observable\",\"at_ns\":1000}"
    );
    assert_eq!(changes[0].to_record(), changes[0].to_record());
}

#[test]
fn mains_cam_silence_walks_silent_then_offline() {
    let mut w = DeviceWatchdog::new();
    w.register("wyze-4-23", DeviceClass::Tutk, None);
    w.observe("wyze-4-23", 1_000);
    // Past grace (2 min) but not hard (10 min): Silent, NOT offline.
    w.evaluate(1_000 + 3 * MIN);
    assert!(matches!(
        w.state_of("wyze-4-23"),
        Some(WatchState::Silent { .. })
    ));
    // Past hard threshold: NotObservable with the honest reason.
    w.evaluate(1_000 + 11 * MIN);
    assert_eq!(
        w.state_of("wyze-4-23"),
        Some(&WatchState::NotObservable {
            reason: WatchOfflineReason::SilentBeyondThreshold
        })
    );
    // The transition sequence is recorded: never-observed → observable →
    // silent → not_observable.
    let kinds: Vec<&str> = w.changes().iter().map(|c| c.to.as_str()).collect();
    assert_eq!(kinds, vec!["observable", "silent", "not_observable"]);
}

#[test]
fn battery_cam_sleeps_without_going_offline() {
    let mut w = DeviceWatchdog::new();
    w.register("aosu-rear-door", DeviceClass::BatteryEventDriven, None);
    w.observe("aosu-rear-door", 1_000);
    // 12 hours quiet: asleep, not silent, not offline.
    w.evaluate(1_000 + 12 * HOUR);
    assert!(matches!(
        w.state_of("aosu-rear-door"),
        Some(WatchState::Asleep { .. })
    ));
    // Past 48 hours: honestly not observable.
    w.evaluate(1_000 + 49 * HOUR);
    assert_eq!(
        w.state_of("aosu-rear-door"),
        Some(&WatchState::NotObservable {
            reason: WatchOfflineReason::SilentBeyondThreshold
        })
    );
}

#[test]
fn recovery_is_recorded_and_unregistered_sightings_are_tracked() {
    let mut w = DeviceWatchdog::new();
    w.register("cam-1", DeviceClass::Onvif, None);
    w.observe("cam-1", 1_000);
    w.evaluate(1_000 + 31 * MIN); // Onvif hard = 30 min
    assert!(matches!(
        w.state_of("cam-1"),
        Some(WatchState::NotObservable { .. })
    ));
    w.observe("cam-1", 1_000 + 32 * MIN);
    assert_eq!(w.state_of("cam-1"), Some(&WatchState::Observable));
    // Recovery is a recorded transition.
    let last = w.changes().last().expect("changes").clone();
    assert!(matches!(last.from, WatchState::NotObservable { .. }));
    assert_eq!(last.to, WatchState::Observable);

    // A sighting of something never registered is tracked, not dropped.
    w.observe("mystery-device", 1_000 + 33 * MIN);
    assert_eq!(
        w.state_of("mystery-device"),
        Some(&WatchState::Observable)
    );
    assert_eq!(
        w.changes().last().expect("changes").class,
        DeviceClass::Unknown
    );
}

#[test]
fn silence_of_one_cam_says_nothing_about_others() {
    let mut w = DeviceWatchdog::new();
    w.register("cam-a", DeviceClass::Tutk, None);
    w.register("cam-b", DeviceClass::Tutk, None);
    w.observe("cam-a", 1_000);
    w.evaluate(1_000 + 11 * MIN);
    assert!(matches!(
        w.state_of("cam-a"),
        Some(WatchState::NotObservable { .. })
    ));
    // cam-b never seen: still NeverObserved, never "clear".
    assert_eq!(
        w.state_of("cam-b"),
        Some(&WatchState::NotObservable {
            reason: WatchOfflineReason::NeverObserved
        })
    );
}
