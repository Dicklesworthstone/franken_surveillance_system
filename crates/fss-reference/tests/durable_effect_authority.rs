#![forbid(unsafe_code)]
//! Explicit owner preparation survives durable replay without default authority or retry drift.

use std::error::Error;
use std::path::PathBuf;

use fss_core::effect::EffectAuthority;
use fss_core::{
    CanonicalDecode, CanonicalEncode, ContentDigest, ContractError, EffectIntent,
    EffectJournalTransition, EffectState, IdempotencyKey, ObligationId, OperationId, TimestampNs,
};
use fss_ledger::{IncompleteTailPolicy, Journal, inspect};
use fss_reference::{
    DurableEffectError, DurableEffectJournal, EFFECT_TRANSITION_RECORD_KIND,
    EFFECT_TRANSITION_V2_RECORD_KIND, EFFECT_TRANSITION_V3_RECORD_KIND,
};

type Test<T = ()> = Result<T, Box<dyn Error>>;

struct Scratch(PathBuf);
impl Scratch {
    fn new(label: &str) -> Test<Self> {
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        for attempt in 0..64 {
            let path = base.join(format!(
                "fss-explicit-authority-{}-{label}-{attempt}",
                std::process::id(),
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("cannot allocate test journal directory".into())
    }
    fn journal(&self) -> PathBuf {
        self.0.join("effects.fssj")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn intent(label: &str) -> Test<EffectIntent> {
    Ok(EffectIntent::new(
        OperationId::parse(format!("operation:explicit:{label}"))?,
        IdempotencyKey::parse(format!("idempotency:explicit:{label}"))?,
        "owner.approved.effect",
        ContentDigest::sha256(b"exact request"),
        ContentDigest::sha256(b"exact preconditions"),
    )?)
}
fn authority() -> Test<EffectAuthority> {
    Ok(EffectAuthority::new(
        "principal:fixture-owner",
        "effect:fixture-exact-scope",
        Some(29),
    )?)
}

#[test]
fn explicit_authority_survives_reopen_and_conflicting_retries_append_nothing() -> Test {
    let scratch = Scratch::new("reopen")?;
    let path = scratch.journal();
    let request = intent("reopen")?;
    let obligation = ObligationId::parse("obligation:explicit:reopen")?;
    let owner = authority()?;
    let prepared;
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        prepared = journal
            .prepare_with_authority(
                request.clone(),
                obligation.clone(),
                "response_retained",
                owner.clone(),
                TimestampNs(10),
            )?
            .clone();
        assert_eq!(prepared.authority, owner);
        journal.transition(
            &request.operation_id,
            EffectState::Committed,
            TimestampNs(11),
            None,
            None,
        )?;
    }
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let observed = journal
        .operation(&request.operation_id)
        .ok_or(ContractError::NotFound)?
        .clone();
    assert_eq!(observed.authority, owner);
    assert_eq!(observed.prepared_at, prepared.prepared_at);
    assert_eq!(observed.state, EffectState::Committed);
    let root = journal.last_root();
    let bytes = std::fs::read(&path)?;
    let retry = journal.prepare_with_authority(
        request.clone(),
        obligation.clone(),
        "response_retained",
        owner.clone(),
        TimestampNs(100),
    )?;
    assert_eq!(retry, &observed);
    for field in 0..6 {
        let mut changed_request = request.clone();
        let mut changed_owner = owner.clone();
        let mut changed_obligation = obligation.clone();
        let mut predicate = "response_retained";
        match field {
            0 => changed_owner.principal = "principal:other-owner".to_owned(),
            1 => changed_owner.capability = "effect:other-scope".to_owned(),
            2 => changed_owner.lease_fence = None,
            3 => changed_obligation = ObligationId::parse("obligation:explicit:other")?,
            4 => predicate = "remote_state_asserted",
            _ => {
                changed_request.precondition_digest =
                    ContentDigest::sha256(b"changed preconditions")
            }
        }
        assert!(
            matches!(
                journal.prepare_with_authority(
                    changed_request,
                    changed_obligation,
                    predicate,
                    changed_owner,
                    TimestampNs(101),
                ),
                Err(DurableEffectError::Contract(
                    ContractError::IdempotencyConflict | ContractError::ObligationConflict
                )),
            ),
            "field {field}"
        );
        assert_eq!(journal.last_root(), root);
        assert_eq!(std::fs::read(&path)?, bytes);
        assert_eq!(journal.operation(&request.operation_id), Some(&observed));
    }
    let disk = inspect(&path)?;
    assert_eq!(disk.records().len(), 2);
    assert_eq!(disk.records()[0].kind(), EFFECT_TRANSITION_V3_RECORD_KIND);
    assert!(matches!(
        EffectJournalTransition::from_canonical_bytes(disk.records()[0].payload())?,
        EffectJournalTransition::PrepareWithAuthority { authority, .. } if authority == owner
    ));
    Ok(())
}

#[test]
fn default_prepare_bytes_and_retry_behavior_survive_mixed_explicit_history() -> Test {
    let scratch = Scratch::new("mixed")?;
    let path = scratch.journal();
    let legacy = intent("legacy")?;
    let legacy_obligation = ObligationId::parse("obligation:explicit:legacy")?;
    let explicit = intent("explicit")?;
    let legacy_receipt;
    let prior_bytes;
    {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        legacy_receipt = journal
            .prepare(
                legacy.clone(),
                legacy_obligation.clone(),
                "legacy_predicate",
                TimestampNs(1),
            )?
            .clone();
        prior_bytes = std::fs::read(&path)?;
        let retried = journal.prepare(
            legacy.clone(),
            ObligationId::parse("obligation:legacy:unused")?,
            "ignored_legacy_retry_predicate",
            TimestampNs(2),
        )?;
        assert_eq!(retried, &legacy_receipt);
        assert_eq!(std::fs::read(&path)?, prior_bytes);
        journal.prepare_with_authority(
            explicit.clone(),
            ObligationId::parse("obligation:explicit:new")?,
            "response_retained",
            authority()?,
            TimestampNs(3),
        )?;
        assert!(std::fs::read(&path)?.starts_with(&prior_bytes));
    }
    let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    assert_eq!(
        journal.operation(&legacy.operation_id),
        Some(&legacy_receipt)
    );
    assert_eq!(legacy_receipt.authority, EffectAuthority::system_default());
    assert_eq!(
        journal
            .operation(&explicit.operation_id)
            .ok_or(ContractError::NotFound)?
            .authority,
        authority()?
    );
    let disk = inspect(&path)?;
    assert_eq!(
        EffectJournalTransition::from_canonical_bytes(disk.records()[0].payload())?,
        EffectJournalTransition::Prepare {
            intent: legacy,
            obligation_id: legacy_obligation,
            terminal_predicate: "legacy_predicate".to_owned(),
            now: TimestampNs(1),
        },
    );
    Ok(())
}

#[test]
fn invalid_explicit_preparations_never_append_an_unreplayable_record() -> Test {
    let scratch = Scratch::new("invalid")?;
    let path = scratch.journal();
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let root = journal.last_root();
    let before = std::fs::read(&path)?;
    for field in 0..5 {
        let mut request = intent("invalid")?;
        let mut owner = authority()?;
        let mut predicate = "response_retained".to_owned();
        match field {
            0 => owner.principal.clear(),
            1 => owner.capability.clear(),
            2 => request.effect_class.clear(),
            3 => predicate.clear(),
            _ => predicate = "x".repeat(fss_core::effect::MAX_TERMINAL_PREDICATE_LEN + 1),
        }
        assert!(matches!(
            journal.prepare_with_authority(
                request,
                ObligationId::parse("obligation:explicit:invalid")?,
                predicate,
                owner,
                TimestampNs(1),
            ),
            Err(DurableEffectError::Contract(
                ContractError::InvalidIdentifier
            )),
        ));
        assert_eq!(journal.last_root(), root);
        assert_eq!(std::fs::read(&path)?, before);
        assert_eq!(journal.operations().count(), 0);
    }
    Ok(())
}

#[test]
fn explicit_authority_records_cannot_be_relabelled_as_legacy_history() -> Test {
    for kind in [
        EFFECT_TRANSITION_RECORD_KIND,
        EFFECT_TRANSITION_V2_RECORD_KIND,
    ] {
        let scratch = Scratch::new(&format!("old-kind-{kind}"))?;
        let path = scratch.journal();
        let record = EffectJournalTransition::PrepareWithAuthority {
            intent: intent("wrong-version")?,
            obligation_id: ObligationId::parse("obligation:explicit:wrong-version")?,
            terminal_predicate: "response_retained".to_owned(),
            authority: authority()?,
            now: TimestampNs(1),
        };
        {
            let mut raw = Journal::open(&path, IncompleteTailPolicy::Reject)?;
            raw.append(kind, &record.try_canonical_bytes()?)?;
        }
        assert!(matches!(
            DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject),
            Err(DurableEffectError::Contract(
                ContractError::InvalidEffectTransition
            )),
        ));
    }
    Ok(())
}
