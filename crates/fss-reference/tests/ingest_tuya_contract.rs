#![forbid(unsafe_code)]
//! LAB-AOSU-6 contract tests: the Tuya event/coverage mapper driven by the
//! fss-tuya simulator (INTEROPERABILITY_LAB §5 — no hardware, no keys beyond
//! test fixtures). Pins the lane's honesty invariants:
//! vendor-derived ≠ ground truth; battery cams never certify Continuous;
//! offline cams are not_observable, never "clear"; unmapped dps stay raw.

use std::collections::BTreeSet;

use fss_core::CaptureInterval;
use fss_core::{
    CoverageContinuity, CoverageStopReason, LedgerAnchor, Plane, ReferenceLedger, TimestampNs,
};
use fss_reference::ingest::tuya::{
    CamInventoryEntry, CamObservability, DpsRegistry, EventKind, OfflineReason, TuyaEventMapper,
    TuyaMapperConfig, WakeTrigger,
};
use fss_tuya::client::{Proto, TuyaClient};
use fss_tuya::sim::{HomebaseSim, SimConfig};

const KEY: [u8; 16] = *b"fss_sim_test_key";
const NONCE: [u8; 16] = *b"0123456789abcdef";

fn iv(n: u8) -> [u8; 12] {
    let mut v = [0u8; 12];
    v[11] = n;
    v
}

fn inventory() -> Vec<CamInventoryEntry> {
    // The bead's 2026-10-07 inventory shape: 4x C8S2EA11 battery cams.
    ["rear-door", "solarium", "front-door", "driveway"]
        .iter()
        .map(|id| CamInventoryEntry {
            cam_id: id.to_string(),
            model: "C8S2EA11".to_string(),
            battery: true,
        })
        .collect()
}

fn mapper() -> TuyaEventMapper {
    TuyaEventMapper::new(TuyaMapperConfig {
        site_lineage: "site:test".to_string(),
        homebase_id: "h2e".to_string(),
        cams: inventory(),
        registry: DpsRegistry::laboratory_fixtures(),
        offline_window_ns: 30_000_000_000,
    })
}

fn interval(ns: i128) -> CaptureInterval {
    CaptureInterval::new(TimestampNs(ns), TimestampNs(ns)).expect("interval")
}

/// Negotiate a client↔sim session and return both ends.
fn session() -> (TuyaClient, HomebaseSim) {
    let mut client = TuyaClient::new(KEY, Proto::V35);
    let mut sim = HomebaseSim::new(SimConfig::v35_homebase());
    let f3 = client.start_session(NONCE, iv(1));
    let resp = sim.handle(&f3);
    let f5 = client
        .negotiate_finish(&resp[0], iv(2))
        .expect("negotiate finish");
    sim.handle(&f5);
    (client, sim)
}

#[test]
fn device_state_maps_to_authority_delta_with_raw_dps() {
    let mut m = mapper();
    let d = m
        .map_device_state(
            "fsssimhomebase00",
            "{\"dps\":{\"101\":\"armed_away\",\"102\":85}}",
            interval(1_000),
        )
        .expect("map device state");
    m.commit_pending().expect("commit");
    let payload = m.custody(&d).expect("custody");
    let text = String::from_utf8_lossy(payload);
    assert!(text.contains("\"type\":\"aosu_device_state\""), "{text}");
    assert!(text.contains("\"102\":85"), "raw dp preserved: {text}");
    assert!(
        text.contains("\"provenance\":\"device_state_report\""),
        "{text}"
    );
    assert!(text.contains("\"ground_truth\":false"), "{text}");
    // The batch committed to the ledger on the Authority plane.
    let batch = &m.ledger().batches()[0];
    assert!(batch.deltas.iter().all(|d| d.plane == Plane::Authority));
    assert!(batch.deltas.iter().any(|d| d.family == "aosu_device_state"));
    assert_eq!(
        batch.computed_digest(),
        batch.batch_digest,
        "digest self-consistent"
    );
}

#[test]
fn event_report_recognizes_registry_dps_and_preserves_unknown_raw() {
    let mut m = mapper();
    // Lab fixture registry knows 104 (motion) and 115 (pir); dp 200 is
    // unmapped and must stay raw with UnknownDp semantics.
    let digests = m
        .map_event_report(
            "rear-door",
            "fsssimhomebase00",
            "{\"dps\":{\"104\":\"motion\",\"115\":1,\"200\":\"mystery\"}}",
            interval(2_000),
        )
        .expect("map event report");
    assert_eq!(digests.len(), 3, "one candidate per dp");
    m.commit_pending().expect("commit");
    let mut saw_motion = false;
    let mut saw_unknown = false;
    for d in &digests {
        let text = String::from_utf8_lossy(m.custody(d).expect("custody"));
        assert!(text.contains("\"provenance\":\"vendor_derived\""), "{text}");
        assert!(text.contains("\"ground_truth\":false"), "{text}");
        if text.contains("\"event_kind\":\"motion\"") {
            saw_motion = true;
        }
        if text.contains("\"event_kind\":\"200\"") && text.contains("\"raw\":\"mystery\"") {
            saw_unknown = true;
        }
    }
    assert!(saw_motion, "registry dp recognized as motion");
    assert!(saw_unknown, "unmapped dp preserved raw, not interpreted");
    // The event made the cam observable (a wake window).
    assert_eq!(
        m.observability("rear-door"),
        Some(&CamObservability::Observable)
    );
}

#[test]
fn video_segment_carries_wake_trigger_provenance() {
    let mut m = mapper();
    let d = m
        .map_video_segment(
            "driveway",
            WakeTrigger::Pir,
            "import:abc123",
            interval(3_000),
            Some(1400),
        )
        .expect("map segment");
    let text = String::from_utf8_lossy(m.custody(&d).expect("custody"));
    assert!(text.contains("\"trigger\":\"pir\""), "{text}");
    assert!(text.contains("\"latency_ms\":1400"), "{text}");
    assert!(
        text.contains("\"provenance\":\"wake_trigger_report\""),
        "{text}"
    );
}

#[test]
fn battery_cam_coverage_never_continuous_and_offline_never_clear() {
    let mut m = mapper();
    let anchor = LedgerAnchor::genesis("site:test");
    let mut domain = BTreeSet::new();
    domain.insert("rear-door:events".to_string());

    // Never observed: Unknown continuity, and absence certifies nothing.
    let w = m
        .coverage_witness(
            "rear-door",
            "no motion",
            domain.clone(),
            7,
            anchor.clone(),
            CoverageStopReason::Complete,
        )
        .expect("witness");
    assert_eq!(w.continuity, CoverageContinuity::Unknown);
    assert!(
        !w.certifies_absence(),
        "never-observed cannot certify absence"
    );
    assert_eq!(w.completeness, fss_core::Completeness::NotObservable);
    assert!(
        w.excluded_domain
            .iter()
            .any(|d| d.contains("never_observed"))
    );

    // After one event (observable + battery): Gapped at best, STILL cannot
    // certify absence — blind intervals are structural.
    m.map_event_report(
        "rear-door",
        "fsssimhomebase00",
        "{\"dps\":{\"104\":\"motion\"}}",
        interval(4_000),
    )
    .expect("event");
    let w = m
        .coverage_witness(
            "rear-door",
            "no motion",
            domain.clone(),
            7,
            anchor.clone(),
            CoverageStopReason::Complete,
        )
        .expect("witness");
    assert_eq!(w.continuity, CoverageContinuity::Gapped);
    assert!(
        !w.certifies_absence(),
        "battery cam can never certify absence"
    );

    // Marked offline: excluded from observed domain, reason carried.
    m.mark_not_observable("rear-door", OfflineReason::Offline, interval(4_500))
        .expect("mark");
    let w = m
        .coverage_witness(
            "rear-door",
            "no motion",
            domain.clone(),
            7,
            anchor,
            CoverageStopReason::Complete,
        )
        .expect("witness");
    assert!(w.observed_domain.is_empty());
    assert!(
        w.excluded_domain
            .iter()
            .any(|d| d.contains("rear-door:offline"))
    );
    assert_eq!(w.observed_generation, 0);
    assert!(!w.certifies_absence());
}

#[test]
fn sim_driven_end_to_end_session_frames_map_to_evidence() {
    let (mut client, mut sim) = session();
    let mut m = mapper();

    // dp_query → device-state delta from the sim's fixture dps.
    let q = client.dp_query(iv(3)).expect("dp_query");
    let resp = sim.handle(&q);
    let inbound = client.handle(&resp[0]).expect("dp inbound");
    let dps = String::from_utf8(inbound.payload).expect("utf8");
    let d = m
        .map_device_state("fsssimhomebase00", &dps, interval(5_000))
        .expect("map state");
    assert!(m.custody(&d).is_some());

    // Unsolicited event → event candidates with registry recognition.
    let ev = sim.event_motion_status().expect("event frame");
    let inbound = client.handle(&ev).expect("event inbound");
    let dps = String::from_utf8(inbound.payload).expect("utf8");
    let digests = m
        .map_event_report("rear-door", "fsssimhomebase00", &dps, interval(6_000))
        .expect("map event");
    assert!(!digests.is_empty());

    // Commit: two families in one canonically ordered batch; replay agrees.
    let batch_id = m.commit_pending().expect("commit").expect("non-empty");
    let batches = m.ledger().batches();
    let batch = batches
        .iter()
        .find(|b| b.batch_id == batch_id)
        .expect("batch");
    assert!(batch.is_canonically_ordered());
    let replayed = ReferenceLedger::replay("site:test", batches.to_vec()).expect("replay");
    assert_eq!(replayed.current().anchor, m.ledger().current().anchor);
}

#[test]
fn unknown_cam_is_a_typed_error_not_a_silent_drop() {
    let mut m = mapper();
    let r = m.map_event_report(
        "not-a-cam",
        "fsssimhomebase00",
        "{\"dps\":{\"104\":\"motion\"}}",
        interval(7_000),
    );
    assert!(r.is_err(), "unknown cam must error, not vanish");
}

#[test]
fn flat_dps_parser_handles_scalars_and_preserves_nested_raw() {
    // via the public mapping paths: strings, numbers, bools all preserved
    let mut m = mapper();
    // Value-aware: "104":"armed,away" is not a qualifying motion token and
    // 102:85 is not below the battery-low bound — only unmapped 103 yields
    // a (raw, uninterpreted) candidate. The splitters comma-in-string
    // handling is still exercised by the preserved value.
    let digests = m
        .map_event_report(
            "solarium",
            "fsssimhomebase00",
            "{\"dps\":{\"104\":\"armed,away\",\"102\":85,\"103\":false}}",
            interval(8_000),
        )
        .expect("scalars incl. comma in string");
    assert_eq!(digests.len(), 1, "only unmapped 103 yields a candidate");
    // Value-aware recognition: a registered dp yields an event candidate
    // ONLY for qualifying values — "104":"idle" is state, not motion. An
    // unregistered dp stays UnknownDp with its token preserved verbatim.
    let r = m.map_event_report(
        "solarium",
        "fsssimhomebase00",
        "{\"dps\":{\"104\":\"idle\",\"209\":{\"also\":1}}}",
        interval(9_000),
    );
    let ds = r.expect("report maps");
    assert_eq!(
        ds.len(),
        1,
        "non-qualifying 104 value produces NO candidate"
    );
    let text = String::from_utf8_lossy(m.custody(&ds[0]).expect("custody")).into_owned();
    assert!(text.contains("\"dp_id\":\"209\""), "{text}");
    assert!(text.contains("\"event_kind\":\"209\""), "{text}");
    assert!(text.contains("\"raw\":{\"also\":1}"), "{text}");
    // Qualifying value: "104":"motion" → the motion candidate.
    let r2 = m.map_event_report(
        "solarium",
        "fsssimhomebase00",
        "{\"dps\":{\"104\":\"motion\"}}",
        interval(9_100),
    );
    let ds2 = r2.expect("qualifying report");
    assert_eq!(ds2.len(), 1);
    let text2 = String::from_utf8_lossy(m.custody(&ds2[0]).expect("custody")).into_owned();
    assert!(text2.contains("\"event_kind\":\"motion\""), "{text2}");
    // Invalid-JSON tokens are preserved as escaped strings, never embedded
    // raw into custody JSON.
    let r3 = m.map_event_report(
        "solarium",
        "fsssimhomebase00",
        "{\"dps\":{\"209\":garbage}}",
        interval(9_200),
    );
    let ds3 = r3.expect("garbage token maps");
    let text3 = String::from_utf8_lossy(m.custody(&ds3[0]).expect("custody")).into_owned();
    assert!(text3.contains("\"raw\":\"garbage\""), "escaped: {text3}");
    let _ = EventKind::Motion; // kind surface stays exercised
}

#[test]
fn empty_report_is_no_event_and_no_observability_claim() {
    // Regression (reviewer-found): {"dps":{}} staged zero candidates but
    // used to bump events_seen and mark the cam observable — letting a
    // mains-cam-shaped claim reach Continuous coverage with no event.
    let mut m = mapper();
    let ds = m
        .map_event_report(
            "rear-door",
            "fsssimhomebase00",
            "{\"dps\":{}}",
            interval(10_000),
        )
        .expect("empty report");
    assert!(ds.is_empty());
    assert_eq!(
        m.observability("rear-door"),
        Some(&CamObservability::NotObservable {
            reason: OfflineReason::NeverObserved
        }),
        "empty report must not flip observability"
    );
}

#[test]
fn restaged_object_coalesces_and_commit_succeeds() {
    // Regression (reviewer-found): two reports for the same (cam, dp) before
    // one commit must NOT stage two generations of one object — the ledger
    // admits one delta per object per batch. The later report supersedes.
    let mut m = mapper();
    m.map_event_report(
        "rear-door",
        "fsssimhomebase00",
        "{\"dps\":{\"104\":\"motion\"}}",
        interval(11_000),
    )
    .expect("first report");
    m.map_event_report(
        "rear-door",
        "fsssimhomebase00",
        "{\"dps\":{\"104\":\"motion\"}}",
        interval(11_500),
    )
    .expect("restaged report");
    let batch = m.commit_pending().expect("commit").expect("non-empty");
    let b = m
        .ledger()
        .batches()
        .iter()
        .find(|b| b.batch_id == batch)
        .expect("batch");
    let ids: Vec<&str> = b.deltas.iter().map(|d| d.object_id.as_str()).collect();
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "one delta per object per batch");
    assert_eq!(m.ledger().current().anchor.commit_sequence, 1);
}
