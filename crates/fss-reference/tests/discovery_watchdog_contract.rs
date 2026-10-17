#![forbid(unsafe_code)]
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
        "{\"type\":\"device_state_change\",\"device\":\"cam-1\",\"class\":\"tutk\",\"from\":\"not_observable\",\"reason\":\"never_observed\",\"to\":\"observable\",\"at_ns\":1000}"
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

#[test]
fn silent_state_does_not_churn_but_counter_moves() {
    let mut w = DeviceWatchdog::new();
    w.register("cam-1", DeviceClass::Tutk, None);
    w.observe("cam-1", 1_000);
    w.evaluate(1_000 + 3 * MIN); // into Silent
    let after_first = w.changes().len();
    // Repeated evaluations while still silent: no new records.
    w.evaluate(1_000 + 4 * MIN);
    w.evaluate(1_000 + 5 * MIN);
    assert_eq!(w.changes().len(), after_first, "silent state must not churn");
    // But the stored counter reflects the latest evaluation.
    match w.state_of("cam-1") {
        Some(WatchState::Silent { silent_for_ns }) => {
            assert_eq!(*silent_for_ns, 5 * MIN);
        }
        other => assert!(false, "expected Silent, got {other:?}"),
    }
}

#[test]
fn reclassification_upgrades_unknown_and_holds_concrete() {
    let mut w = DeviceWatchdog::new();
    // Sighting before classification: Unknown class (60-min hard silence).
    w.observe("mystery", 1_000);
    assert_eq!(
        w.state_of("mystery"),
        Some(&WatchState::Observable),
    );
    // Discovery identifies it as TUTK: class upgrades, thresholds follow.
    w.register("mystery", DeviceClass::Tutk, None);
    w.evaluate(1_000 + 11 * MIN); // past TUTK hard (10 min), under Unknown's 60
    assert_eq!(
        w.state_of("mystery"),
        Some(&WatchState::NotObservable {
            reason: WatchOfflineReason::SilentBeyondThreshold
        }),
        "upgraded class thresholds apply"
    );
    // A conflicting concrete reclassification is NOT honored (flip-flop
    // protection). Discriminated by thresholds: re-register as Onvif
    // (30-min hard) — if the class stayed TUTK (10-min hard), 11 minutes
    // of silence after the next sighting is offline; had it flip-flopped
    // to Onvif it would only be Silent.
    w.register("mystery", DeviceClass::Onvif, None);
    w.observe("mystery", 1_000 + 12 * MIN);
    w.evaluate(1_000 + 23 * MIN);
    assert_eq!(
        w.state_of("mystery"),
        Some(&WatchState::NotObservable {
            reason: WatchOfflineReason::SilentBeyondThreshold
        }),
        "concrete class is stable (TUTK thresholds, not Onvif flip-flop)"
    );
}

#[test]
fn record_text_escapes_device_identity() {
    let mut w = DeviceWatchdog::new();
    w.register("weird\"id", DeviceClass::Unknown, None);
    w.observe("weird\"id", 1_000);
    let rec = w.changes().last().expect("change").to_record();
    assert!(rec.contains("\"weird\\\"id\""), "escaped: {rec}");
}

#[test]
fn older_sighting_never_regresses_and_backward_eval_holds_state() {
    let mut w = DeviceWatchdog::new();
    w.register("cam-1", DeviceClass::Tutk, None);
    w.observe("cam-1", 20 * MIN);
    // A LATE-Arriving older sighting must not move the clock backward.
    w.observe("cam-1", 5 * MIN);
    w.evaluate(21 * MIN);
    // silent_for = 21-20 = 1 min → still Observable (not 21-5=16 min offline)
    assert_eq!(w.state_of("cam-1"), Some(&WatchState::Observable));
    // Backward evaluation (before the last sighting): state holds, no record.
    w.evaluate(10 * MIN);
    assert_eq!(w.state_of("cam-1"), Some(&WatchState::Observable));
    assert_eq!(w.changes().len(), 1, "no phantom records from time travel");
}

#[test]
fn records_carry_reason_and_duration() {
    let mut w = DeviceWatchdog::new();
    w.register("cam-1", DeviceClass::Tutk, None);
    w.observe("cam-1", 1_000);
    w.evaluate(1_000 + 3 * MIN);
    let silent_rec = w.changes().last().expect("silent transition").to_record();
    assert!(silent_rec.contains("\"silent_for_ns\":"), "{silent_rec}");
    w.evaluate(1_000 + 11 * MIN);
    let offline_rec = w.changes().last().expect("offline transition").to_record();
    assert!(
        offline_rec.contains("\"reason\":\"silent_beyond_threshold\""),
        "{offline_rec}"
    );
    // The never-observed → observable record names WHAT it recovered from
    // (from-side reason), which is exactly what a consumer needs.
    let first = &w.changes()[0].to_record();
    assert!(first.contains("\"reason\":\"never_observed\""), "{first}");
}
