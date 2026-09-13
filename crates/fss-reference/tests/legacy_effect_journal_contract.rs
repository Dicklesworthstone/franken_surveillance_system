#![forbid(unsafe_code)]
//! fss-deir9: an effect journal written before an indeterminate reason was required still opens,
//! and the durable path never writes a record that the journal would then refuse.

use std::error::Error;
use std::path::{Path, PathBuf};

use fss_core::{
    CanonicalEncode, ContentDigest, ContractError, EffectIntent, EffectJournalTransition,
    EffectState, IdempotencyKey, IndeterminateEffectReason, ObligationId, OperationId, TimestampNs,
};
use fss_ledger::{IncompleteTailPolicy, Journal};
use fss_reference::{DurableEffectJournal, EFFECT_TRANSITION_RECORD_KIND};

/// A scratch directory removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> Result<Self, Box<dyn Error>> {
        let dir = std::env::temp_dir().join(format!(
            "fss-legacy-effect-journal-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn journal_path(&self) -> PathBuf {
        self.0.join("effect.journal")
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn operation(name: &str) -> Result<OperationId, Box<dyn Error>> {
    Ok(OperationId::parse(format!("operation:alert:{name}"))?)
}

fn intent(name: &str) -> Result<EffectIntent, Box<dyn Error>> {
    Ok(EffectIntent {
        operation_id: operation(name)?,
        idempotency_key: IdempotencyKey::parse(format!("idempotency:alert:{name}"))?,
        effect_class: "alert.dispatch".to_owned(),
        request_digest: ContentDigest::sha256(format!("{name}-request").as_bytes()),
        precondition_digest: ContentDigest::sha256(format!("{name}-precondition").as_bytes()),
    })
}

fn obligation(name: &str) -> Result<ObligationId, Box<dyn Error>> {
    Ok(ObligationId::parse(format!("obligation:alert:{name}"))?)
}

/// Appends `records` exactly as a journal written by an earlier release would hold them.
fn write_records(path: &Path, records: &[EffectJournalTransition]) -> Result<(), Box<dyn Error>> {
    let mut journal = Journal::open(path, IncompleteTailPolicy::Reject)?;
    for record in records {
        let _ = journal.append(
            EFFECT_TRANSITION_RECORD_KIND,
            &record.try_canonical_bytes()?,
        )?;
    }
    Ok(())
}

/// A bystander operation, then an operation committed and marked indeterminate with the given
/// (missing or empty) reason, as the public durable `transition` could write before 37859dc.
fn legacy_records(
    error_code: Option<String>,
) -> Result<Vec<EffectJournalTransition>, Box<dyn Error>> {
    Ok(vec![
        EffectJournalTransition::Prepare {
            intent: intent("bystander")?,
            obligation_id: obligation("bystander")?,
            terminal_predicate: "delivery_proved".to_owned(),
            now: TimestampNs(5),
        },
        EffectJournalTransition::Prepare {
            intent: intent("legacy")?,
            obligation_id: obligation("legacy")?,
            terminal_predicate: "delivery_proved".to_owned(),
            now: TimestampNs(10),
        },
        EffectJournalTransition::Transition {
            operation_id: operation("legacy")?,
            next: EffectState::Committed,
            now: TimestampNs(20),
            result_digest: None,
            error_code: None,
        },
        EffectJournalTransition::Transition {
            operation_id: operation("legacy")?,
            next: EffectState::Indeterminate,
            now: TimestampNs(30),
            result_digest: None,
            error_code,
        },
    ])
}

#[test]
fn legacy_reasonless_indeterminate_journal_still_opens() -> Result<(), Box<dyn Error>> {
    for (label, error_code) in [("none", None), ("empty", Some(String::new()))] {
        let dir = ScratchDir::new(label)?;
        let path = dir.journal_path();
        write_records(&path, &legacy_records(error_code.clone())?)?;
        let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let legacy = journal
            .operation(&operation("legacy")?)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(legacy.state, EffectState::Indeterminate, "{label}");
        // The persisted entry is kept as recorded; no reason is invented for it, and the missing
        // reason is explicit.
        assert_eq!(legacy.error_code, error_code, "{label}");
        assert_eq!(
            legacy.indeterminate_reason,
            Some(IndeterminateEffectReason::Unrecorded),
            "{label}"
        );
        let bystander = journal
            .operation(&operation("bystander")?)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(bystander.state, EffectState::Prepared, "{label}");
    }
    Ok(())
}

#[test]
fn new_reasonless_indeterminate_is_refused_before_it_is_written() -> Result<(), Box<dyn Error>> {
    let dir = ScratchDir::new("fresh")?;
    let path = dir.journal_path();
    let legacy = operation("legacy")?;
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(
            intent("legacy")?,
            obligation("legacy")?,
            "delivery_proved",
            TimestampNs(10),
        )?;
        let _ = journal.transition(&legacy, EffectState::Committed, TimestampNs(20), None, None)?;
        let before = std::fs::metadata(&path)?.len();
        for error_code in [None, Some(String::new())] {
            let refused = journal.transition(
                &legacy,
                EffectState::Indeterminate,
                TimestampNs(30),
                None,
                error_code.clone(),
            );
            assert!(refused.is_err(), "{error_code:?}: {refused:?}");
        }
        assert_eq!(
            std::fs::metadata(&path)?.len(),
            before,
            "a refused transition writes no record"
        );
    }
    let reopened = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let receipt = reopened.operation(&legacy).ok_or(ContractError::NotFound)?;
    assert_eq!(receipt.state, EffectState::Committed);
    Ok(())
}
