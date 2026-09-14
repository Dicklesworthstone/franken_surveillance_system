#![forbid(unsafe_code)]
//! Contract tests for world-fact authority derived from an opened `DurableReferenceLedger` (fss-sz0cc).
//!
//! Threat model: type-level discipline against accidental or stale authority. Code in the same
//! process that can write the deployment can always forge durable state, so the goal is that no
//! public API turns a rewound or in-memory ledger into world-fact authority by mistake.

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::abstraction::{AuthorityAnchor, AuthorityContext, CurrentAnchorSource};
use fss_core::contract_basis::reference_contract_basis;
use fss_core::{
    BatchId, CaptureInterval, Completeness, ContentDigest, ContractError, CoverageContinuity,
    CoverageStopReason, CoverageWitness, EvidenceDelta, LedgerAnchor, NegativeReadClaim,
    NegativeReadOutcome, ObjectId, Plane, TimestampNs, evaluate_negative_read,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy};

const SITE: &str = "site:us-east:primary";

fn temp_journal(label: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "durable_world_fact_authority_contract-{label}.journal"
    ))
}

fn witness_at(anchor: &LedgerAnchor) -> CoverageWitness {
    let mut d = BTreeSet::new();
    d.insert("zone:north_perimeter".to_string());
    CoverageWitness {
        anchor: anchor.clone(),
        authorized_domain: d.clone(),
        observed_domain: d,
        excluded_domain: BTreeSet::new(),
        continuity: CoverageContinuity::Continuous,
        completeness: Completeness::Complete,
        negative_predicate: "no_unauthorized_intrusion".to_string(),
        stop_reason: CoverageStopReason::Complete,
        authorized_generation: 1,
        observed_generation: 1,
    }
}

fn claim_at(anchor: &LedgerAnchor, witness: CoverageWitness) -> NegativeReadClaim {
    let mut d = BTreeSet::new();
    d.insert("zone:north_perimeter".to_string());
    NegativeReadClaim {
        claim_id: "neg_claim:durable_contract".to_string(),
        query_predicate: "no_unauthorized_intrusion".to_string(),
        anchor: anchor.clone(),
        target_domain: d,
        target_generation: 1,
        coverage_witness: Some(witness),
    }
}

fn advance_durable(ledger: &mut DurableReferenceLedger, tag: &str) -> Result<(), Box<dyn Error>> {
    let delta = EvidenceDelta {
        delta_id: format!("delta:{tag}"),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse(&format!("object:{tag}"))?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(tag.as_bytes()),
        witness_digest: None,
        operation_id: None,
    };
    let batch = ledger.prepare_batch(BatchId::parse(&format!("batch:{tag}"))?, vec![delta], [])?;
    ledger.append(batch)?;
    Ok(())
}

#[test]
fn test_honest_head_from_opened_durable_ledger_accepted() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("honest-head-accepted");
    let _ = fs::remove_file(&path);

    let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    advance_durable(&mut durable, "entry_1")?;

    let head_anchor = durable.current().anchor.clone();
    assert_eq!(head_anchor.commit_sequence, 1);

    let auth_ledger = durable.authoritative_ledger()?;
    let authority = AuthorityAnchor::from_committed_head(&auth_ledger)?;
    assert_eq!(authority.current_anchor(), &head_anchor);

    let witness = witness_at(&head_anchor);
    let claim = claim_at(&head_anchor, witness.clone());
    let res = evaluate_negative_read(&claim, &authority);
    assert!(res.is_ok(), "honest head claim must be accepted: {res:?}");

    let basis = reference_contract_basis();
    let ctx = AuthorityContext::from_committed_head(&basis, &auth_ledger)?;
    assert_eq!(ctx.current_anchor(), &head_anchor);
    let res_ctx = evaluate_negative_read(&claim, &ctx);
    assert!(
        res_ctx.is_ok(),
        "honest ctx claim must be accepted: {res_ctx:?}"
    );

    let outcome = NegativeReadOutcome::from_witness(
        "neg_claim:durable_contract",
        "no_unauthorized_intrusion",
        head_anchor.clone(),
        claim.target_domain,
        &witness,
        &authority,
        1,
    );
    assert!(
        outcome.is_ok(),
        "outcome from honest witness must be accepted: {outcome:?}"
    );

    let _ = fs::remove_file(&path);
    Ok(())
}

#[test]
fn test_reopening_after_more_batches_gives_new_head_and_old_authority_refused_as_stale()
-> Result<(), Box<dyn Error>> {
    let path = temp_journal("reopen-gives-new-head-stale-refused");
    let _ = fs::remove_file(&path);

    // 1. Open and commit batch 1
    let head1_anchor;
    let auth1;
    {
        let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
        advance_durable(&mut durable, "seq_1")?;
        head1_anchor = durable.current().anchor.clone();
        assert_eq!(head1_anchor.commit_sequence, 1);
        let auth_ledger1 = durable.authoritative_ledger()?;
        auth1 = AuthorityAnchor::from_committed_head(&auth_ledger1)?;
    }

    // 2. Reopen and append batch 2
    let head2_anchor;
    let auth2;
    {
        let mut durable = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
        assert_eq!(durable.current().anchor, head1_anchor);
        advance_durable(&mut durable, "seq_2")?;
        head2_anchor = durable.current().anchor.clone();
        assert_eq!(head2_anchor.commit_sequence, 2);
        let auth_ledger2 = durable.authoritative_ledger()?;
        auth2 = AuthorityAnchor::from_committed_head(&auth_ledger2)?;
    }

    // 3. Stale claim at sequence 1 evaluated against authority at sequence 2 MUST be refused as StaleAnchor
    let claim1 = claim_at(&head1_anchor, witness_at(&head1_anchor));
    assert!(
        evaluate_negative_read(&claim1, &auth1).is_ok(),
        "claim at sequence 1 must be accepted against authority 1"
    );
    let res_stale = evaluate_negative_read(&claim1, &auth2);
    assert_eq!(
        res_stale.err(),
        Some(ContractError::StaleAnchor),
        "claim at old sequence 1 against authority at sequence 2 must be StaleAnchor"
    );

    // 4. Honest claim at sequence 2 evaluated against authority at sequence 2 MUST be accepted
    let claim2 = claim_at(&head2_anchor, witness_at(&head2_anchor));
    assert_eq!(
        evaluate_negative_read(&claim2, &auth1).err(),
        Some(ContractError::StaleAnchor),
        "claim at sequence 2 evaluated against old authority 1 must be refused as StaleAnchor"
    );
    let res_honest = evaluate_negative_read(&claim2, &auth2);
    assert!(
        res_honest.is_ok(),
        "claim at current sequence 2 against authority 2 must be accepted"
    );

    // 5. Reopen again without changes: head matches sequence 2
    let reopened = DurableReferenceLedger::open(&path, SITE, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.current().anchor, head2_anchor);
    let auth_reopened = AuthorityAnchor::from_committed_head(&reopened.authoritative_ledger()?)?;
    assert_eq!(auth_reopened.current_anchor(), &head2_anchor);

    // Stale claim against reopened authority is still refused
    let res_reopened_stale = evaluate_negative_read(&claim1, &auth_reopened);
    assert_eq!(res_reopened_stale.err(), Some(ContractError::StaleAnchor));

    // Current claim against reopened authority is accepted
    let res_reopened_honest = evaluate_negative_read(&claim2, &auth_reopened);
    assert!(res_reopened_honest.is_ok());

    let _ = fs::remove_file(&path);
    Ok(())
}
