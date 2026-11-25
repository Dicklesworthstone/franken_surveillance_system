#![forbid(unsafe_code)]
//! Contract & fault tests for `FSS-134` (`fss-x4a.13.18`): archive Decision Cards for path,
//! repair overhead, and object chunk sizing (`docs/ATP_ARCHIVE_AND_REPLICATION.md` §3, §5, §6, §11).

use fss_core::{ContentDigest, TimestampNs};
use fss_object::archive_decision_card::{
    ARCHIVE_CARD_MAGIC, ARCHIVE_CARD_VERSION, ATP_ARCHIVE_DECISION_CARD_DOMAIN, ArchiveCardError,
    ArchiveCardGuidance, ArchiveDecisionCard, ArchiveDecisionCardBuilder, ArchiveDecisionKind,
    ArchiveHardClamps, ArchiveOptionSpec, ArchivePlanningAuthority, PricingManifestRef,
};
use fss_object::multipath::PathKind;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

fn default_clamps() -> ArchiveHardClamps {
    ArchiveHardClamps {
        allowed_residency_zones: ["local".to_owned(), "us-east".to_owned()]
            .into_iter()
            .collect(),
        min_failure_domains: 2,
        min_loss_tolerance_bps: 1_500,
        max_verification_memory_bytes: 64 * 1024 * 1024,
        max_total_cost_micros: 100_000,
        require_privacy_authorized: true,
        require_integrity_verified: true,
    }
}

fn pricing_ref() -> PricingManifestRef {
    PricingManifestRef {
        manifest_digest: ContentDigest::sha256(b"pricing-manifest-2026-08-31-v1"),
        effective_date: "2026-08-31".to_owned(),
        source_label: "r2-and-b2-operator-manifest-v1".to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn opt(
    id: &str,
    kind: PathKind,
    zone: &str,
    domains: u32,
    priv_ok: bool,
    geom: Option<(u32, u32, u32)>,
    loss_bps: u32,
    cost: u64,
    lat: u64,
    overhead: u32,
    mem: u64,
) -> ArchiveOptionSpec {
    ArchiveOptionSpec {
        option_id: id.to_owned(),
        path_kind: kind,
        residency_zone: zone.to_owned(),
        failure_domains: domains,
        privacy_authorized: priv_ok,
        integrity_verified: true,
        chunk_bytes: 4 * 1024 * 1024,
        repair_geometry: geom,
        keyframe_aligned: true,
        loss_tolerance_bps: loss_bps,
        total_cost_micros: cost,
        latency_ms: lat,
        overhead_bps: overhead,
        verification_memory_bytes: mem,
        expected_proof: "post_repair_canonical_digest_and_retrievability_sample".to_owned(),
    }
}

#[test]
fn hard_clamps_pareto_frontier_permutation_invariance_and_wire_codec() -> TestResult {
    let basis = ContentDigest::sha256(b"basis:archive-card-134");
    let auth = ArchivePlanningAuthority::active(basis, 3, 2);

    let options = vec![
        // Clamped: cheapest but privacy unauthorized!
        opt(
            "opt-cheap-unauth",
            PathKind::CloudProvider,
            "us-east",
            3,
            false,
            Some((65_536, 16, 4)),
            2_500,
            100,
            10,
            2_500,
            4_000_000,
        ),
        // Clamped: invalid GF(256) geometry (k + r = 300 > 255)!
        opt(
            "opt-bad-gf256",
            PathKind::RepairSource,
            "us-east",
            2,
            true,
            Some((65_536, 200, 100)),
            3_000,
            2_000,
            50,
            5_000,
            16_000_000,
        ),
        // Clamped: single failure domain (< min 2)!
        opt(
            "opt-single-domain",
            PathKind::LocalDisk,
            "local",
            1,
            true,
            Some((65_536, 16, 4)),
            2_000,
            500,
            5,
            2_500,
            2_000_000,
        ),
        // Frontier A: low cost, higher latency & overhead
        opt(
            "opt-frontier-low-cost",
            PathKind::CloudProvider,
            "us-east",
            2,
            true,
            Some((65_536, 16, 4)),
            2_000,
            10_000,
            120,
            2_500,
            8_000_000,
        ),
        // Frontier B: faster latency & lower overhead, higher cost
        opt(
            "opt-frontier-low-lat",
            PathKind::LanPeer,
            "local",
            2,
            true,
            Some((32_768, 20, 4)),
            1_666,
            25_000,
            20,
            2_000,
            4_000_000,
        ),
        // Dominated by Frontier A on ALL 4 objectives!
        opt(
            "opt-dominated",
            PathKind::CloudProvider,
            "us-east",
            2,
            true,
            Some((65_536, 16, 6)),
            2_000,
            15_000,
            180,
            3_750,
            16_000_000,
        ),
    ];
    let mut rev_options = options.clone();
    rev_options.reverse();

    let invalidators = vec![
        "pricing_manifest_digest_change".to_owned(),
        "residency_policy_epoch_change".to_owned(),
    ];

    let card_fwd = ArchiveDecisionCardBuilder::evaluate(
        "card:repair-sizing-01",
        ArchiveDecisionKind::RepairOverheadSizing,
        &auth,
        pricing_ref(),
        &default_clamps(),
        options,
        invalidators.clone(),
        TimestampNs(10_000),
        false,
    )?;
    let card_rev = ArchiveDecisionCardBuilder::evaluate(
        "card:repair-sizing-01",
        ArchiveDecisionKind::RepairOverheadSizing,
        &auth,
        pricing_ref(),
        &default_clamps(),
        rev_options,
        invalidators,
        TimestampNs(10_000),
        false,
    )?;

    assert_eq!(card_fwd, card_rev);
    assert_eq!(card_fwd.clamped_rejections.len(), 3);
    assert_eq!(card_fwd.nondominated_frontier.len(), 2);
    assert_eq!(
        card_fwd.nondominated_frontier[0].option_id,
        "opt-frontier-low-cost"
    );
    assert_eq!(
        card_fwd.nondominated_frontier[1].option_id,
        "opt-frontier-low-lat"
    );
    assert_eq!(card_fwd.dominated_options.len(), 1);
    assert_eq!(card_fwd.dominated_options[0].option_id, "opt-dominated");
    assert_eq!(
        card_fwd.dominated_options[0].dominated_by,
        "opt-frontier-low-cost"
    );
    assert_eq!(
        ATP_ARCHIVE_DECISION_CARD_DOMAIN,
        "fss.atp_archive_decision_card.v1"
    );

    // Wire codec round-trip (`FSSADC01` v1).
    let wire = card_fwd.to_canonical_bytes()?;
    assert_eq!(&wire[..8], &ARCHIVE_CARD_MAGIC);
    assert_eq!(
        u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]),
        ARCHIVE_CARD_VERSION
    );
    assert_eq!(ArchiveDecisionCard::from_canonical_bytes(&wire)?, card_fwd);

    emit_caplog(
        "fss134_clamps_pareto_frontier_and_wire",
        "hard_clamps_pareto_nondominated_frontier_and_wire_verified",
        "hard_clamps_pareto_nondominated_frontier_and_wire_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn decision_card_refuses_effect_authority_all_clamped_cancel_and_hostile_wire() -> TestResult {
    let basis = ContentDigest::sha256(b"basis:archive-card-faults");
    let auth = ArchivePlanningAuthority::active(basis, 1, 1);

    // 1. Effect authority escalation fails closed (`XFER-INV-006`).
    let mut escalated = auth.clone();
    escalated.grants_effect_authority = true;
    let err = ArchiveDecisionCardBuilder::evaluate(
        "card:escalated",
        ArchiveDecisionKind::PathSelection,
        &escalated,
        pricing_ref(),
        &default_clamps(),
        vec![opt(
            "ok",
            PathKind::CloudProvider,
            "us-east",
            2,
            true,
            None,
            2_000,
            1_000,
            10,
            0,
            1_000,
        )],
        vec![],
        TimestampNs(100),
        false,
    )
    .expect_err("effect authority on decision card must fail closed");
    assert!(matches!(err, ArchiveCardError::AuthorityRefused(_)));
    assert_eq!(
        err.guidance(),
        ArchiveCardGuidance::ReauthorizePlanningContext
    );

    // 2. All options clamped -> AllOptionsClamped.
    assert_eq!(
        ArchiveDecisionCardBuilder::evaluate(
            "card:all-clamped",
            ArchiveDecisionKind::ObjectChunkSizing,
            &auth,
            pricing_ref(),
            &default_clamps(),
            vec![opt(
                "disallowed-eu",
                PathKind::CloudProvider,
                "eu-west",
                2,
                true,
                None,
                2_000,
                1_000,
                10,
                0,
                1_000,
            )],
            vec![],
            TimestampNs(100),
            false,
        ),
        Err(ArchiveCardError::AllOptionsClamped { clamped_count: 1 })
    );

    // 3. Cooperative cancellation returns Cancelled.
    assert_eq!(
        ArchiveDecisionCardBuilder::evaluate(
            "card:cancel",
            ArchiveDecisionKind::ObjectChunkSizing,
            &auth,
            pricing_ref(),
            &default_clamps(),
            vec![],
            vec![],
            TimestampNs(100),
            true,
        ),
        Err(ArchiveCardError::Cancelled)
    );

    // 4. Hostile wire decoding on `FSSADC01`.
    let card = ArchiveDecisionCardBuilder::evaluate(
        "card:wire-test",
        ArchiveDecisionKind::PathSelection,
        &auth,
        pricing_ref(),
        &default_clamps(),
        vec![opt(
            "ok",
            PathKind::CloudProvider,
            "us-east",
            2,
            true,
            None,
            2_000,
            1_000,
            10,
            0,
            1_000,
        )],
        vec!["pricing_change".to_owned()],
        TimestampNs(500),
        false,
    )?;
    let wire = card.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        ArchiveDecisionCard::from_canonical_bytes(&bad_magic),
        Err(ArchiveCardError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&5_u32.to_be_bytes());
    assert_eq!(
        ArchiveDecisionCard::from_canonical_bytes(&bad_ver),
        Err(ArchiveCardError::UnsupportedVersion { version: 5 })
    );
    assert!(matches!(
        ArchiveDecisionCard::from_canonical_bytes(&wire[..wire.len() - 5]),
        Err(ArchiveCardError::MalformedWire(_))
    ));
    let mut bit_flip = wire.clone();
    let last = bit_flip.len() - 1;
    bit_flip[last] ^= 0x01;
    assert_eq!(
        ArchiveDecisionCard::from_canonical_bytes(&bit_flip),
        Err(ArchiveCardError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0x00);
    assert!(matches!(
        ArchiveDecisionCard::from_canonical_bytes(&trailing),
        Err(ArchiveCardError::MalformedWire(_))
    ));

    emit_caplog(
        "fss134_faults_authority_clamped_cancel_and_wire",
        "decision_card_faults_and_wire_refusals_verified",
        "decision_card_faults_and_wire_refusals_verified",
        "pass",
    );
    Ok(())
}
