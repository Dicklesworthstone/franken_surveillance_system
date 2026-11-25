#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-129` (`fss-x4a.13.13`): multipath transfer race and
//! loser-drain protocol (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §5, `XFER-INV-007`, `XFER-INV-008`).

use std::collections::BTreeSet;

use fss_core::{ContentDigest, TimestampNs};
use fss_object::atp_lifecycle::{PathState, TransferId};
use fss_object::multipath::{
    ATP_MULTIPATH_RACE_RECEIPT_DOMAIN, MULTIPATH_RECEIPT_MAGIC, MULTIPATH_RECEIPT_VERSION,
    MultipathCandidate, MultipathError, MultipathGuidance, MultipathRaceCoordinator,
    MultipathRaceReceipt, MultipathRaceState, PathKind, PathPolicyClamp, RaceAuthorityContext,
    RacePathRole,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn default_policy() -> PathPolicyClamp {
    PathPolicyClamp {
        allowed_residency_zones: ["local".to_owned(), "us-east".to_owned()]
            .into_iter()
            .collect(),
        allowed_kinds: [
            PathKind::LocalDisk,
            PathKind::LanPeer,
            PathKind::CloudProvider,
            PathKind::RepairSource,
        ]
        .into_iter()
        .collect(),
        max_egress_cost_micros: 5_000,
        max_latency_ms: 500,
        max_concurrent_hedges: 2,
        require_privacy_authorized: true,
        require_integrity_verified: true,
    }
}

#[allow(clippy::too_many_arguments)]
fn cand(
    id: &str,
    kind: PathKind,
    domain: &str,
    zone: &str,
    priv_ok: bool,
    integ_ok: bool,
    lat: u64,
    cost: u64,
) -> MultipathCandidate {
    MultipathCandidate {
        path_id: id.to_owned(),
        kind,
        failure_domain: domain.to_owned(),
        residency_zone: zone.to_owned(),
        privacy_authorized: priv_ok,
        integrity_verified: integ_ok,
        estimated_latency_ms: lat,
        estimated_egress_cost_micros: cost,
    }
}

fn make_transfer_id(tag: &str) -> TransferId {
    TransferId::derive(
        1,
        "node-north",
        "archive-east",
        42,
        ContentDigest::sha256(tag.as_bytes()),
        ContentDigest::sha256(b"basis:seq10"),
        ContentDigest::sha256(b"policy:v1"),
    )
}

#[test]
fn policy_clamps_diverse_hedging_corrupt_quarantine_and_mandatory_loser_drain() -> TestResult {
    let payload = b"canonical-immutable-camera-segment-payload-fss129".to_vec();
    let target_digest = ContentDigest::sha256(&payload);
    let basis_digest = ContentDigest::sha256(b"basis:seq10");
    let auth = RaceAuthorityContext::active(basis_digest, 4, 2);
    let transfer_id = make_transfer_id("race-happy-and-corrupt");

    // Include faster unauthorized / out-of-residency / over-cost paths that MUST be clamped BEFORE racing!
    let candidates = vec![
        // Fastest (1ms) but privacy unauthorized -> MUST be clamped!
        cand(
            "path-fast-unauth",
            PathKind::LanPeer,
            "dom-z",
            "local",
            false,
            true,
            1,
            0,
        ),
        // Second fastest (2ms) but disallowed residency zone -> MUST be clamped!
        cand(
            "path-fast-foreign",
            PathKind::CloudProvider,
            "dom-eu",
            "eu-central",
            true,
            true,
            2,
            100,
        ),
        // Over egress budget (9_999 > 5_000) -> MUST be clamped!
        cand(
            "path-expensive",
            PathKind::CloudProvider,
            "dom-cost",
            "us-east",
            true,
            true,
            5,
            9_999,
        ),
        // Authorized primary candidate (10ms, dom-a)
        cand(
            "path-lan-a",
            PathKind::LanPeer,
            "dom-a",
            "local",
            true,
            true,
            10,
            50,
        ),
        // Same failure domain as primary (12ms, dom-a) -> hedge MUST prefer distinct domain `dom-b`!
        cand(
            "path-lan-a2",
            PathKind::LanPeer,
            "dom-a",
            "local",
            true,
            true,
            12,
            60,
        ),
        // Distinct failure domain (20ms, dom-b) -> MUST be selected for diverse hedge!
        cand(
            "path-cloud-b",
            PathKind::CloudProvider,
            "dom-b",
            "us-east",
            true,
            true,
            20,
            400,
        ),
    ];

    let mut race = MultipathRaceCoordinator::plan(
        transfer_id,
        target_digest,
        payload.len() as u64,
        default_policy(),
        &auth,
        candidates,
        TimestampNs(1_000),
        false,
    )?;

    assert_eq!(race.state(), MultipathRaceState::Planned);
    assert_eq!(race.clamped_rejections().len(), 3);
    let clamped_ids: BTreeSet<&str> = race
        .clamped_rejections()
        .iter()
        .map(|r| r.path_id.as_str())
        .collect();
    assert_eq!(
        clamped_ids,
        ["path-expensive", "path-fast-foreign", "path-fast-unauth"]
            .into_iter()
            .collect()
    );
    assert_eq!(race.paths().len(), 3);

    // 1. Launch primary (`path-lan-a`, lowest latency in authorized set).
    let primary = race.launch_next_path(&auth, TimestampNs(1_100), false)?;
    assert_eq!(primary, "path-lan-a");
    assert_eq!(race.paths()["path-lan-a"].state, PathState::Active);
    assert_eq!(race.paths()["path-lan-a"].role, RacePathRole::Primary);

    // 2. Launch hedge -> MUST choose `path-cloud-b` (distinct failure domain `dom-b`) over `path-lan-a2` (`dom-a`)!
    let hedge = race.launch_next_path(&auth, TimestampNs(1_200), false)?;
    assert_eq!(hedge, "path-cloud-b");
    assert_eq!(race.paths()["path-cloud-b"].state, PathState::Active);
    assert_eq!(race.paths()["path-cloud-b"].role, RacePathRole::Hedged);

    // 3. Concurrency cap (`max_concurrent_hedges == 2`) refuses a 3rd simultaneous hedge.
    assert!(matches!(
        race.launch_next_path(&auth, TimestampNs(1_250), false),
        Err(MultipathError::HedgeLimitOrExhausted(_))
    ));

    // 4. Primary returns CORRUPT bytes -> MUST quarantine `path-lan-a` (`Suspect` + `Quarantined`) instead of completing!
    let mut corrupt = payload.clone();
    corrupt[0] ^= 0xFF;
    let corrupt_err = race
        .declare_winner_with_bytes("path-lan-a", &auth, &corrupt, TimestampNs(1_300))
        .expect_err("corrupt fast path must be quarantined");
    assert!(matches!(
        corrupt_err,
        MultipathError::CorruptWinnerQuarantined { ref path_id, .. } if path_id == "path-lan-a"
    ));
    assert_eq!(
        corrupt_err.guidance(),
        MultipathGuidance::QuarantineAndRetryAlternatePath
    );
    assert_eq!(race.paths()["path-lan-a"].state, PathState::Suspect);
    assert_eq!(race.paths()["path-lan-a"].role, RacePathRole::Quarantined);
    assert!(!race.paths()["path-lan-a"].state.can_expose_data());
    // Launch backup `path-lan-a2` now that concurrency dropped back to 1.
    let backup = race.launch_next_path(&auth, TimestampNs(1_350), false)?;
    assert_eq!(backup, "path-lan-a2");

    // 5. Hedged path `path-cloud-b` delivers exact verified canonical bytes!
    //    `path-lan-a2` and `path-lan-a` both enter `Draining` until their resources hit 0!
    let post_win_state =
        race.declare_winner_with_bytes("path-cloud-b", &auth, &payload, TimestampNs(1_400))?;
    assert_eq!(
        post_win_state,
        MultipathRaceState::WinnerVerifiedDrainingLosers
    );
    assert_eq!(race.paths()["path-cloud-b"].state, PathState::Closed);
    assert_eq!(race.paths()["path-cloud-b"].role, RacePathRole::Winner);
    assert_eq!(race.paths()["path-lan-a2"].state, PathState::Draining);
    assert_eq!(race.paths()["path-lan-a"].state, PathState::Draining);

    // 6. XFER-INV-008: Finalizing BEFORE losers & quarantined paths release sockets/temps/billing MUST FAIL CLOSED!
    let leak_err = race
        .finalize_receipt(TimestampNs(1_450))
        .expect_err("cannot finalize with unreleased loser resources");
    assert_eq!(
        leak_err,
        MultipathError::LoserDrainIncomplete {
            remaining_paths: 2,
            leaked_sockets: 2,
            leaked_temp_objects: 2,
            leaked_billing_ops: 2,
        }
    );
    assert_eq!(leak_err.guidance(), MultipathGuidance::DrainRemainingPaths);

    // 7. Drain both `path-lan-a2` and `path-lan-a` cleanly to `PathState::Closed`.
    assert_eq!(
        race.drain_path("path-lan-a2", 1, 1, 1, TimestampNs(1_500))?,
        PathState::Closed
    );
    assert_eq!(
        race.state(),
        MultipathRaceState::WinnerVerifiedDrainingLosers
    );
    assert_eq!(
        race.drain_path("path-lan-a", 1, 1, 1, TimestampNs(1_550))?,
        PathState::Closed
    );
    assert_eq!(race.state(), MultipathRaceState::Complete);

    // 8. Finalize sealed receipt + binary wire round-trip (`FSSMP001` v1).
    let receipt = race.finalize_receipt(TimestampNs(1_600))?;
    assert_eq!(receipt.state, MultipathRaceState::Complete);
    assert_eq!(receipt.winner_path_id.as_deref(), Some("path-cloud-b"));
    assert_eq!(receipt.losers_drained_clean, 2);
    assert_eq!(receipt.paths_quarantined, 1);
    assert_eq!(receipt.total_launched_cost_micros, 50 + 400 + 60);
    assert_eq!(
        ATP_MULTIPATH_RACE_RECEIPT_DOMAIN,
        "fss.atp_multipath_race_receipt.v1"
    );

    let wire = receipt.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &MULTIPATH_RECEIPT_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        MULTIPATH_RECEIPT_VERSION
    );
    assert_eq!(MultipathRaceReceipt::from_canonical_bytes(&wire)?, receipt);

    emit_caplog(
        "fss129_clamps_hedge_quarantine_and_loser_drain",
        "clamps_enforced_corrupt_quarantined_and_zero_leaked_losers",
        "clamps_enforced_corrupt_quarantined_and_zero_leaked_losers",
        "pass",
    );
    Ok(())
}

#[test]
fn cancellation_drain_indeterminate_stuck_loser_authority_and_hostile_wire() -> TestResult {
    let payload = b"fss129-fault-and-cancel-payload".to_vec();
    let target_digest = ContentDigest::sha256(&payload);
    let basis_digest = ContentDigest::sha256(b"basis:seq20");
    let auth = RaceAuthorityContext::active(basis_digest, 7, 1);
    let transfer_id = make_transfer_id("race-cancel-faults");

    // 1. All candidates clamped -> fails closed with NoAuthorizedPaths.
    let err_none = MultipathRaceCoordinator::plan(
        transfer_id,
        target_digest,
        payload.len() as u64,
        default_policy(),
        &auth,
        vec![cand(
            "only-unauth",
            PathKind::CloudProvider,
            "d1",
            "us-east",
            false,
            true,
            5,
            10,
        )],
        TimestampNs(100),
        false,
    )
    .expect_err("zero compliant paths must fail closed");
    assert_eq!(
        err_none,
        MultipathError::NoAuthorizedPaths { clamped_count: 1 }
    );

    // 2. XFER-INV-006: Effect authority escalation in race context fails closed.
    let mut bad_auth = auth.clone();
    bad_auth.grants_effect_authority = true;
    assert_eq!(
        MultipathRaceCoordinator::plan(
            transfer_id,
            target_digest,
            payload.len() as u64,
            default_policy(),
            &bad_auth,
            vec![cand(
                "ok-path",
                PathKind::LocalDisk,
                "d1",
                "local",
                true,
                true,
                5,
                0,
            )],
            TimestampNs(100),
            false,
        )
        .expect_err("effect escalation must refuse"),
        MultipathError::AuthorityEscalationRefused
    );

    // 3. Cooperative cancellation drains active + hedged paths cleanly before `CancelledClean`.
    let mut race = MultipathRaceCoordinator::plan(
        transfer_id,
        target_digest,
        payload.len() as u64,
        default_policy(),
        &auth,
        vec![
            cand("p1", PathKind::LanPeer, "d1", "local", true, true, 10, 10),
            cand(
                "p2",
                PathKind::CloudProvider,
                "d2",
                "us-east",
                true,
                true,
                20,
                20,
            ),
        ],
        TimestampNs(200),
        false,
    )?;
    race.launch_next_path(&auth, TimestampNs(210), false)?;
    race.launch_next_path(&auth, TimestampNs(220), false)?;
    assert_eq!(
        race.request_cancel("operator_cancelled_transfer", TimestampNs(230))?,
        MultipathRaceState::CancelledDraining
    );
    // Finalizing before draining refuses with LoserDrainIncomplete!
    assert!(matches!(
        race.finalize_receipt(TimestampNs(240)),
        Err(MultipathError::LoserDrainIncomplete {
            remaining_paths: 2,
            ..
        })
    ));
    race.drain_path("p1", 1, 1, 1, TimestampNs(250))?;
    race.drain_path("p2", 1, 1, 1, TimestampNs(260))?;
    assert_eq!(race.state(), MultipathRaceState::CancelledClean);
    let cancel_receipt = race.finalize_receipt(TimestampNs(270))?;
    assert_eq!(cancel_receipt.state, MultipathRaceState::CancelledClean);
    assert!(cancel_receipt.winner_path_id.is_none());

    // 4. Stuck loser drain -> explicitly recorded as `Indeterminate`, NEVER `Complete`!
    let mut stuck = MultipathRaceCoordinator::plan(
        transfer_id,
        target_digest,
        payload.len() as u64,
        default_policy(),
        &auth,
        vec![
            cand("p1", PathKind::LanPeer, "d1", "local", true, true, 10, 10),
            cand(
                "p2",
                PathKind::CloudProvider,
                "d2",
                "us-east",
                true,
                true,
                20,
                20,
            ),
        ],
        TimestampNs(300),
        false,
    )?;
    stuck.launch_next_path(&auth, TimestampNs(310), false)?;
    stuck.launch_next_path(&auth, TimestampNs(320), false)?;
    stuck.declare_winner_with_bytes("p1", &auth, &payload, TimestampNs(330))?;
    stuck.mark_drain_indeterminate("p2", "remote_abort_timeout", TimestampNs(340))?;
    let indet_receipt = stuck.finalize_receipt(TimestampNs(350))?;
    assert_eq!(indet_receipt.state, MultipathRaceState::Indeterminate);
    assert!(indet_receipt.winner_path_id.is_none());

    // 5. Hostile wire decoding on `FSSMP001`.
    let wire = indet_receipt.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        MultipathRaceReceipt::from_canonical_bytes(&bad_magic),
        Err(MultipathError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&42_u32.to_be_bytes());
    assert_eq!(
        MultipathRaceReceipt::from_canonical_bytes(&bad_ver),
        Err(MultipathError::UnsupportedVersion { version: 42 })
    );
    assert!(matches!(
        MultipathRaceReceipt::from_canonical_bytes(&wire[..wire.len() - 6]),
        Err(MultipathError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        MultipathRaceReceipt::from_canonical_bytes(&bit_flip),
        Err(MultipathError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x00);
    assert!(matches!(
        MultipathRaceReceipt::from_canonical_bytes(&trailing),
        Err(MultipathError::MalformedWire(_))
    ));

    emit_caplog(
        "fss129_cancel_indeterminate_authority_and_wire",
        "cancel_drain_indeterminate_escalation_and_wire_refusals_verified",
        "cancel_drain_indeterminate_escalation_and_wire_refusals_verified",
        "pass",
    );
    Ok(())
}
