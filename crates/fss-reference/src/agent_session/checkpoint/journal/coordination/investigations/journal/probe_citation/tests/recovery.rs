#![forbid(unsafe_code)]
//! Lost output, ambiguous append and hostile complete history retain their distinct outcomes.

use super::*;
use crate::agent_session::checkpoint::journal::SessionAppendRecovery;
use fss_ledger::{AppendPhase, IncompleteTailPolicy, Journal};
use std::fs::OpenOptions;
use std::io::Write;

#[test]
fn historical_lookup_survives_case_progress_and_original_session_closure_without_native_grants()
-> TestResult {
    let mut f = Fixture::new()?;
    let delivery = f.native(false)?;
    let receipt = f.cite(&delivery)?;
    let citation_root = f.store.committed_root();
    let next = f.store.investigate(
        &f.session.principal_id,
        &f.session.session_id,
        InvestigationCommand::Change {
            case_id: f.target.case_id.clone(),
            expected: receipt.revision().digest(),
            change: InvestigationChange::Activate,
        },
        TimestampNs(10),
    )?;
    f.store.close(
        &f.session.principal_id,
        &f.session.session_id,
        TimestampNs(10),
    )?;
    let mut reader = params("session:historical-reader")?;
    reader.capabilities.insert(CASE_WRITE.to_owned());
    f.store.open(reader.clone(), basis(), TimestampNs(10))?;
    let mut f = f.reopen()?;
    let inspection = f.store.inspect_probe_citation(
        &reader.principal_id,
        &reader.session_id,
        &f.target,
        &f.registration.subscription_id,
        RECEIPT_CEILING,
        TimestampNs(10),
    )?;
    assert_eq!(inspection.receipt(), Some(&receipt));
    assert_eq!(inspection.citation_root(), Some(citation_root));
    assert_eq!(f.store.investigation_heads(), vec![next]);
    assert_eq!(f.retained()?, delivery.subscription);
    assert_eq!(
        f.store.charge_probe_citation_inspection(
            &reader.principal_id,
            &reader.session_id,
            &f.target,
            fss_core::AgentView::Case,
            7,
            TimestampNs(10)
        )?,
        93
    );
    assert_eq!(f.retained()?, delivery.subscription);
    assert!(f.inspect(RECEIPT_CEILING).is_err());
    assert!(
        f.store
            .charge_probe_citation_inspection(
                &reader.principal_id,
                &reader.session_id,
                &f.target,
                fss_core::AgentView::Case,
                94,
                TimestampNs(10)
            )
            .is_err()
    );
    assert_eq!(
        f.store.remaining_token_budget(
            &reader.principal_id,
            &reader.session_id,
            TimestampNs(10)
        )?,
        93
    );
    Ok(())
}

#[test]
fn current_case_visibility_and_case_write_gate_historical_receipt_and_projection_charge()
-> TestResult {
    for scenario in 0..6 {
        let mut f = Fixture::new()?;
        let delivery = f.native(false)?;
        f.cite(&delivery)?;
        let mut reader = params("session:historical-reader")?;
        reader.capabilities.insert(CASE_WRITE.to_owned());
        match scenario {
            0 => reader.principal_id = PrincipalId::parse("principal:other")?,
            1 => reader.mission_id = fss_core::MissionId::parse("mission:other")?,
            2 => reader.privacy_scope.clear(),
            3 => {
                reader.capabilities.remove(CASE_WRITE);
            }
            4 => {
                reader.capabilities.remove("CAP-AGENT-INVESTIGATE-001");
            }
            _ => {}
        }
        f.store.open(reader.clone(), basis(), TimestampNs(10))?;
        if scenario == 5 {
            f.store
                .close(&reader.principal_id, &reader.session_id, TimestampNs(10))?;
        }
        assert!(
            f.store
                .inspect_probe_citation(
                    &reader.principal_id,
                    &reader.session_id,
                    &f.target,
                    &f.registration.subscription_id,
                    RECEIPT_CEILING,
                    TimestampNs(10)
                )
                .is_err()
        );
        assert!(
            f.store
                .charge_probe_citation_inspection(
                    &reader.principal_id,
                    &reader.session_id,
                    &f.target,
                    fss_core::AgentView::Case,
                    1,
                    TimestampNs(10)
                )
                .is_err()
        );
        assert_eq!(f.retained()?, delivery.subscription);
    }
    Ok(())
}

#[test]
fn exact_target_lookup_and_complete_receipt_limit_never_repeat_native_work() -> TestResult {
    let mut f = Fixture::new()?;
    let delivery = f.native(false)?;
    let receipt = f.cite(&delivery)?;
    let required = f.inspect(RECEIPT_CEILING)?.receipt_bytes();
    assert!(required > receipt.revision().try_canonical_bytes()?.len());
    assert!(f.inspect(required - 1).is_err());
    assert_eq!(f.inspect(required)?.receipt(), Some(&receipt));
    for scenario in 0..4 {
        let mut target = f.target.clone();
        let mut subscription = f.registration.subscription_id.clone();
        match scenario {
            0 => target.expected = ContentDigest::sha256(b"other predecessor"),
            1 => target.hypothesis = "hypothesis:b".into(),
            2 => target.contradicts = true,
            _ => subscription = "probe:other".into(),
        }
        let inspected = f.store.inspect_probe_citation(
            &f.session.principal_id,
            &f.session.session_id,
            &target,
            &subscription,
            0,
            TimestampNs(10),
        )?;
        assert!(inspected.receipt().is_none());
        assert!(inspected.citation_root().is_none());
        assert_eq!(inspected.receipt_bytes(), 0);
    }
    assert_eq!(f.retained()?, delivery.subscription);
    assert_eq!(
        f.store.remaining_token_budget(
            &f.session.principal_id,
            &f.session.session_id,
            TimestampNs(10)
        )?,
        100
    );
    Ok(())
}

#[test]
fn every_link_append_cut_recovers_without_repeating_or_refunding_native_work() -> TestResult {
    for (phase, committed) in [
        (AppendPhase::BodyWrite, false),
        (AppendPhase::BodySync, false),
        (AppendPhase::CommitWrite, true),
        (AppendPhase::CommitSync, true),
    ] {
        let mut f = Fixture::new()?;
        let delivery = f.native(false)?;
        f.store.journal.fail_after_phase(phase);
        assert!(f.cite(&delivery).is_err());
        let before = fs::read(f.path())?;
        assert!(f.inspect(RECEIPT_CEILING).is_err());
        assert_eq!(fs::read(f.path())?, before);
        assert_eq!(
            f.store.reconcile_pending(IncompleteTailPolicy::Truncate)?,
            if committed {
                SessionAppendRecovery::Committed
            } else {
                SessionAppendRecovery::NotCommitted
            }
        );
        let mut f = f.reopen()?;
        let inspection = f.inspect(RECEIPT_CEILING)?;
        assert_eq!(inspection.receipt().is_some(), committed);
        assert_eq!(f.retained()?, delivery.subscription);
        assert_eq!(f.retained()?.attempts_reserved(), 1);
        assert_eq!(
            f.store.investigation_heads()[0].digest() == f.target.expected,
            !committed
        );
    }
    Ok(())
}

#[test]
fn published_but_unlinked_report_remains_pending_and_inspection_does_not_finish_the_case()
-> TestResult {
    let mut f = Fixture::new()?;
    let delivery = f.native(false)?;
    let mut f = f.reopen()?;
    assert!(f.inspect(0)?.receipt().is_none());
    assert_eq!(f.retained()?, delivery.subscription);
    assert_eq!(f.store.investigation_heads()[0].digest(), f.target.expected);
    Ok(())
}

#[test]
fn forged_native_root_command_configuration_payload_or_case_cas_refuses_before_tail_repair()
-> TestResult {
    for scenario in 0..7 {
        let mut f = Fixture::new()?;
        let delivery = f.native(false)?;
        let mut receipt = f.cite(&delivery)?;
        let report = fss_ledger::inspect(f.store.path())?;
        let after = f.store.checkpoint_digest;
        match scenario {
            0 => receipt.custody.native_root = ContentDigest::sha256(b"another native root"),
            1 => receipt.custody.native.command = ContentDigest::sha256(b"another command"),
            2 => receipt.custody.native.configuration = ContentDigest::sha256(b"another recipe"),
            3 => receipt.custody.native.payload = ContentDigest::sha256(b"another payload"),
            4 => receipt.custody.native.pending = ContentDigest::sha256(b"another pending receipt"),
            5 => {
                receipt.custody.native.subscription_state =
                    ContentDigest::sha256(b"another progress state")
            }
            _ => receipt.target.expected = ContentDigest::sha256(b"another case predecessor"),
        }
        let path = f.directory.0.join("forged.fssj");
        let mut forged = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        for record in &report.records()[..report.records().len() - 1] {
            forged.append(record.kind(), record.payload())?;
        }
        forged.append(
            COORDINATION_COMMAND_RECORD_KIND,
            &codec::encode(&receipt, after)?,
        )?;
        let root = forged.last_root();
        drop(forged);
        let mut tail = OpenOptions::new().append(true).open(&path)?;
        tail.write_all(b"FSSJ")?;
        tail.sync_all()?;
        drop(tail);
        let before = fs::read(&path)?;
        assert!(
            DurableSessionStore::recover_existing_with_coordination(
                &path,
                root,
                DurableSessionLimits::default(),
                WorkClaimLimits::default(),
                IncompleteTailPolicy::Truncate
            )
            .is_err()
        );
        assert_eq!(fs::read(&path)?, before);
    }
    Ok(())
}

#[test]
fn corrupt_complete_history_refuses_before_any_inspection_or_output_charge_append() -> TestResult {
    let mut f = Fixture::new()?;
    let delivery = f.native(false)?;
    f.cite(&delivery)?;
    let mut bytes = fs::read(f.path())?;
    bytes[100] ^= 1;
    fs::write(f.path(), &bytes)?;
    assert!(f.inspect(RECEIPT_CEILING).is_err());
    assert!(
        f.store
            .charge_probe_citation_inspection(
                &f.session.principal_id,
                &f.session.session_id,
                &f.target,
                fss_core::AgentView::Case,
                1,
                TimestampNs(10)
            )
            .is_err()
    );
    assert_eq!(fs::read(f.path())?, bytes);
    Ok(())
}

#[test]
fn historical_projection_uses_exact_selected_view_ceiling_and_one_lifetime_allowance() -> TestResult
{
    let mut f = Fixture::new()?;
    let delivery = f.native(false)?;
    f.cite(&delivery)?;
    let mut reader = params("session:forensic-reader")?;
    reader.capabilities.insert(CASE_WRITE.to_owned());
    reader.token_budget = 20_000;
    f.store.open(reader.clone(), basis(), TimestampNs(10))?;
    for (view, tokens) in [
        (fss_core::AgentView::Case, 5001),
        (fss_core::AgentView::Forensic, 16001),
        (fss_core::AgentView::Brief, 1),
    ] {
        let before = fs::read(f.path())?;
        assert!(
            f.store
                .charge_probe_citation_inspection(
                    &reader.principal_id,
                    &reader.session_id,
                    &f.target,
                    view,
                    tokens,
                    TimestampNs(10),
                )
                .is_err()
        );
        assert_eq!(fs::read(f.path())?, before);
    }
    assert_eq!(
        f.store.charge_probe_citation_inspection(
            &reader.principal_id,
            &reader.session_id,
            &f.target,
            fss_core::AgentView::Forensic,
            6000,
            TimestampNs(10),
        )?,
        14_000
    );
    assert_eq!(
        f.store.charge_probe_citation_inspection(
            &reader.principal_id,
            &reader.session_id,
            &f.target,
            fss_core::AgentView::Case,
            7,
            TimestampNs(10),
        )?,
        13_993
    );
    assert_eq!(f.retained()?, delivery.subscription);
    Ok(())
}
