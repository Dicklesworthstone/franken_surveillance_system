#![forbid(unsafe_code)]
//! Contract, differential lattice oracle, tombstone, crash-safe persistence, authority,
//! cancellation, and hostile-wire tests for `FSS-036` (`fss-x4a.9.6`).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fss_core::{ContentDigest, ObjectId, Plane, TimestampNs};
use fss_ledger::{
    HoldObligation, HoldState, HoldTarget, LEDGER_RETENTION_HOLD_TABLE_DOMAIN,
    RETENTION_HOLD_WIRE_MAGIC, RETENTION_HOLD_WIRE_VERSION, RetentionClass, RetentionDisposition,
    RetentionHoldError, RetentionHoldTable, RetentionRule, StorageAuthorityScope,
    TableMutationOutcome,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn unique_tmp_path(tag: &str) -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("fss_036_{tag}_{pid}_{n}"));
    let _ = fs::create_dir_all(&dir);
    dir.join("retention_holds.fss")
}

fn emit_caplog(step: &str, expected: &str, observed: &str, verdict: &str) {
    println!(
        "CAPLOG {{\"step\":\"{step}\",\"expected\":\"{expected}\",\"observed\":\"{observed}\",\"verdict\":\"{verdict}\"}}"
    );
}

#[test]
fn retention_lattice_holds_tombstones_oracle_and_atomic_reload() -> TestResult {
    assert_eq!(
        LEDGER_RETENTION_HOLD_TABLE_DOMAIN,
        "fss.ledger_retention_hold_table.v1"
    );

    let cb = ContentDigest::sha256(b"cb-fss-036");
    let auth = StorageAuthorityScope::active(cb, 1, 1, [Plane::Authority]);
    let mut table = RetentionHoldTable::new("site:fss-036")?;

    // Adopt overlapping rules: broad 1_000ns window + narrower front-cam 5_000ns window!
    let rule_all = RetentionRule {
        rule_id: "rule:source:default".to_owned(),
        object_prefix: "obj:cam:".to_owned(),
        class: RetentionClass::SourceCustody,
        min_retain_ns: 500,
        max_retain_ns: 1_000,
        authority_generation: 1,
        policy_epoch: 1,
        approval_digest: ContentDigest::sha256(b"approve-default"),
    };
    let rule_front = RetentionRule {
        rule_id: "rule:source:front-extended".to_owned(),
        object_prefix: "obj:cam:front:".to_owned(),
        class: RetentionClass::SourceCustody,
        min_retain_ns: 2_000,
        max_retain_ns: 5_000,
        authority_generation: 1,
        policy_epoch: 1,
        approval_digest: ContentDigest::sha256(b"approve-front"),
    };
    assert_eq!(
        table.adopt_rule(&auth, rule_all.clone(), false)?,
        TableMutationOutcome::Inserted
    );
    // Idempotent duplicate rule adoption succeeds cleanly!
    assert_eq!(
        table.adopt_rule(&auth, rule_all.clone(), false)?,
        TableMutationOutcome::AlreadyPresent
    );
    assert_eq!(
        table.adopt_rule(&auth, rule_front.clone(), false)?,
        TableMutationOutcome::Inserted
    );

    let obj_front = ObjectId::parse("obj:cam:front:seg-01")?;
    let obj_rear = ObjectId::parse("obj:cam:rear:seg-01")?;
    let obj_uncovered = ObjectId::parse("obj:audit:unmatched")?;
    let created = TimestampNs(10_000);

    // Conservative lattice join: at t = 12_000, obj_rear expired under 1_000ns rule,
    // while obj_front is STILL retained until 15_000 under the more conservative 5_000ns rule!
    let disp_rear = table.evaluate_disposition(
        &auth,
        &obj_rear,
        RetentionClass::SourceCustody,
        created,
        TimestampNs(12_000),
        false,
    )?;
    assert!(!disp_rear.grants_deletion_authority());
    assert_eq!(
        disp_rear,
        RetentionDisposition::EligibleForDeletionPlan {
            rule_id: "rule:source:default".to_owned(),
            expired_at: TimestampNs(11_000),
        }
    );

    let disp_front = table.evaluate_disposition(
        &auth,
        &obj_front,
        RetentionClass::SourceCustody,
        created,
        TimestampNs(12_000),
        false,
    )?;
    assert_eq!(
        disp_front,
        RetentionDisposition::RetainedWithinWindow {
            rule_id: "rule:source:front-extended".to_owned(),
            retain_until: TimestampNs(15_000),
        }
    );

    // Uncovered scope fails closed (IndeterminateUncovered, NEVER deletable)!
    let disp_unc = table.evaluate_disposition(
        &auth,
        &obj_uncovered,
        RetentionClass::SourceCustody,
        created,
        TimestampNs(99_000),
        false,
    )?;
    assert!(matches!(
        disp_unc,
        RetentionDisposition::IndeterminateUncovered { .. }
    ));
    assert!(!disp_unc.is_eligible_for_deletion_plan());

    // Place an active indefinite exact hold + a time-bounded prefix hold on obj_rear!
    let hold_exact = HoldObligation {
        hold_id: "hold:incident:001".to_owned(),
        target: HoldTarget::ExactObject(obj_rear.clone()),
        reason: "owner incident preservation".to_owned(),
        placed_at: TimestampNs(10_500),
        expires_at: None,
        authority_generation: 1,
        approval_digest: ContentDigest::sha256(b"approve-hold-1"),
        state: HoldState::Active,
    };
    let hold_prefix = HoldObligation {
        hold_id: "hold:legal:prefix-rear".to_owned(),
        target: HoldTarget::ObjectPrefix("obj:cam:rear:".to_owned()),
        reason: "temporary review hold".to_owned(),
        placed_at: TimestampNs(10_600),
        expires_at: Some(TimestampNs(20_000)),
        authority_generation: 1,
        approval_digest: ContentDigest::sha256(b"approve-hold-2"),
        state: HoldState::Active,
    };
    assert_eq!(
        table.place_hold(&auth, hold_exact.clone(), false)?,
        TableMutationOutcome::Inserted
    );
    assert_eq!(
        table.place_hold(&auth, hold_exact, false)?,
        TableMutationOutcome::AlreadyPresent
    );
    assert_eq!(
        table.place_hold(&auth, hold_prefix, false)?,
        TableMutationOutcome::Inserted
    );
    assert_eq!(table.active_hold_count(TimestampNs(15_000)), 2);

    // Active holds DOMINATE expiry at t = 15_000 (both holds blocking)!
    let blocked = table.evaluate_disposition(
        &auth,
        &obj_rear,
        RetentionClass::SourceCustody,
        created,
        TimestampNs(15_000),
        false,
    )?;
    assert_eq!(
        blocked,
        RetentionDisposition::BlockedByActiveHold {
            hold_ids: vec![
                "hold:incident:001".to_owned(),
                "hold:legal:prefix-rear".to_owned(),
            ],
        }
    );

    // At t = 20_000, time-bounded prefix hold expires, indefinite exact hold STILL blocks!
    let blocked_after_prefix_exp = table.evaluate_disposition(
        &auth,
        &obj_rear,
        RetentionClass::SourceCustody,
        created,
        TimestampNs(20_000),
        false,
    )?;
    assert_eq!(
        blocked_after_prefix_exp,
        RetentionDisposition::BlockedByActiveHold {
            hold_ids: vec!["hold:incident:001".to_owned()],
        }
    );

    // Explicitly release indefinite hold -> tombstoned in table (NEVER deleted!), object now eligible!
    let rel_approval = ContentDigest::sha256(b"release-hold-1");
    assert_eq!(
        table.release_hold(
            &auth,
            "hold:incident:001",
            TimestampNs(21_000),
            rel_approval,
            "incident resolved by owner",
            false,
        )?,
        TableMutationOutcome::Released
    );
    assert_eq!(
        table.release_hold(
            &auth,
            "hold:incident:001",
            TimestampNs(21_000),
            rel_approval,
            "incident resolved by owner",
            false,
        )?,
        TableMutationOutcome::AlreadyReleased
    );
    assert!(matches!(
        table.holds().get("hold:incident:001").map(|h| &h.state),
        Some(HoldState::Released { .. })
    ));

    // Differential check against independent naive oracle across boundary timestamps!
    let raw_rules: Vec<RetentionRule> = table.rules().values().cloned().collect();
    let raw_holds: Vec<HoldObligation> = table.holds().values().cloned().collect();
    for oid in [&obj_front, &obj_rear, &obj_uncovered] {
        for ts in [
            9_999, 10_000, 10_999, 11_000, 14_999, 15_000, 19_999, 20_000, 22_000,
        ] {
            let live = table.evaluate_disposition(
                &auth,
                oid,
                RetentionClass::SourceCustody,
                created,
                TimestampNs(ts),
                false,
            )?;
            let oracle = RetentionHoldTable::oracle_evaluate_disposition(
                &raw_rules,
                &raw_holds,
                oid,
                RetentionClass::SourceCustody,
                created,
                TimestampNs(ts),
            );
            assert_eq!(live, oracle, "lattice disagreed with oracle at ts={ts}");
        }
    }

    // Atomic durable save + verified reload + wire determinism (`FSSRHT01` v1)!
    let path = unique_tmp_path("atomic_reload");
    table.save_atomic(&path)?;
    let reloaded = RetentionHoldTable::load_verified(&path)?;
    assert_eq!(reloaded, table);
    let w1 = table.to_canonical_bytes()?;
    let w2 = reloaded.to_canonical_bytes()?;
    assert_eq!(w1, w2);
    assert_eq!(&w1[..8], &RETENTION_HOLD_WIRE_MAGIC);
    assert_eq!(
        u32::from_be_bytes([w1[8], w1[9], w1[10], w1[11]]),
        RETENTION_HOLD_WIRE_VERSION
    );

    emit_caplog(
        "fss_036_retention_lattice_holds_oracle_and_reload",
        "holds_dominate_tombstones_preserved_oracle_matched_and_atomic_reload_verified",
        "holds_dominate_tombstones_preserved_oracle_matched_and_atomic_reload_verified",
        "pass",
    );
    Ok(())
}

#[test]
fn retention_hold_authority_conflicts_cancel_and_hostile_wire_fail_closed() -> TestResult {
    let cb = ContentDigest::sha256(b"cb-fss-036-faults");
    let auth = StorageAuthorityScope::active(cb, 1, 1, [Plane::Authority]);
    let cog_only = StorageAuthorityScope::active(cb, 1, 1, [Plane::Cognition]);
    let mut table = RetentionHoldTable::new("site:fss-036-faults")?;

    let rule = RetentionRule {
        rule_id: "rule:a".to_owned(),
        object_prefix: "obj:".to_owned(),
        class: RetentionClass::DerivedEvent,
        min_retain_ns: 100,
        max_retain_ns: 200,
        authority_generation: 1,
        policy_epoch: 1,
        approval_digest: ContentDigest::sha256(b"a"),
    };

    // 1. Cognition-only plane & cooperative cancellation fail closed!
    assert!(matches!(
        table.adopt_rule(&cog_only, rule.clone(), false),
        Err(RetentionHoldError::AuthorityRefused(_))
    ));
    assert_eq!(
        table.adopt_rule(&auth, rule.clone(), true),
        Err(RetentionHoldError::Cancelled)
    );
    assert!(table.rules().is_empty());

    // 2. Conflicting rule_id mutation fails closed with IdConflict!
    table.adopt_rule(&auth, rule.clone(), false)?;
    let mut modified_rule = rule;
    modified_rule.max_retain_ns = 999;
    assert_eq!(
        table.adopt_rule(&auth, modified_rule, false),
        Err(RetentionHoldError::IdConflict {
            id: "rule:a".to_owned(),
        })
    );

    // 3. Releasing unknown hold fails closed with UnknownHold!
    assert_eq!(
        table.release_hold(
            &auth,
            "hold:nonexistent",
            TimestampNs(1_000),
            ContentDigest::sha256(b"rel"),
            "nope",
            false,
        ),
        Err(RetentionHoldError::UnknownHold {
            hold_id: "hold:nonexistent".to_owned(),
        })
    );

    // 4. Hostile wire decoding on `FSSRHT01`: bad magic, bad version, truncation, bit flip, trailing byte!
    let wire = table.to_canonical_bytes()?;
    let mut bad_magic = wire.clone();
    bad_magic[0] ^= 0xFF;
    assert_eq!(
        RetentionHoldTable::from_canonical_bytes(&bad_magic),
        Err(RetentionHoldError::InvalidMagic)
    );
    let mut bad_ver = wire.clone();
    bad_ver[8..12].copy_from_slice(&4_u32.to_be_bytes());
    assert_eq!(
        RetentionHoldTable::from_canonical_bytes(&bad_ver),
        Err(RetentionHoldError::UnsupportedVersion { version: 4 })
    );
    assert!(matches!(
        RetentionHoldTable::from_canonical_bytes(&wire[..wire.len() - 4]),
        Err(RetentionHoldError::MalformedWire(_))
    ));
    let mut flipped = wire.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert_eq!(
        RetentionHoldTable::from_canonical_bytes(&flipped),
        Err(RetentionHoldError::ChecksumMismatch)
    );
    let mut trailing = wire;
    trailing.push(0xEE);
    assert!(matches!(
        RetentionHoldTable::from_canonical_bytes(&trailing),
        Err(RetentionHoldError::MalformedWire(_))
    ));

    emit_caplog(
        "fss_036_faults_authority_conflict_cancel_wire",
        "plane_refusal_cancel_id_conflict_unknown_hold_and_wire_failed_closed",
        "plane_refusal_cancel_id_conflict_unknown_hold_and_wire_failed_closed",
        "pass",
    );
    Ok(())
}
