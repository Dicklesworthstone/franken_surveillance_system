#![forbid(unsafe_code)]
//! fss-deir9: an effect journal written before an indeterminate reason was required still opens,
//! and the durable path never writes a record that the journal would then refuse.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

use fss_core::effect::EffectAuthority;
use fss_core::{
    BatchId, CanonicalDecode, CanonicalDecoder, CanonicalEncode, CanonicalEncoder, CaptureInterval,
    ContentDigest, ContractError, EffectCancellationRecord, EffectIntent, EffectJournal,
    EffectJournalTransition, EffectRecordVersion, EffectState, EvidenceDelta, IdempotencyKey,
    IndeterminateEffectReason, ObjectId, ObligationId, ObligationState, OperationId,
    OperationReceipt, Plane, PreparedEffect, TimestampNs,
};
use fss_ledger::{DurableReferenceLedger, IncompleteTailPolicy, Journal, JournalRecord, inspect};
use fss_reference::{
    ALERT_OUTCOME_FAMILY, DurableEffectError, DurableEffectJournal, EFFECT_TRANSITION_RECORD_KIND,
    EFFECT_TRANSITION_V2_RECORD_KIND, EFFECT_TRANSITION_V3_RECORD_KIND, ObligationLedgerState,
};

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

/// Appends each record under its own journal record kind, which names its version.
fn write_kind_records(
    path: &Path,
    records: &[(u16, EffectJournalTransition)],
) -> Result<(), Box<dyn Error>> {
    let mut journal = Journal::open(path, IncompleteTailPolicy::Reject)?;
    for (kind, record) in records {
        let _ = journal.append(*kind, &record.try_canonical_bytes()?)?;
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
            assert!(
                matches!(
                    refused,
                    Err(DurableEffectError::Contract(
                        ContractError::EvidenceRequired
                    ))
                ),
                "{error_code:?}: {refused:?}"
            );
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

/// fss-deir9 (D3), through the sealed durable replay (fss-8dnfo): the unmarked public replay
/// applies the current rules only. The legacy rules are reachable only for records a durable journal
/// file names v1, and never after a v2 record. The versioned replay itself is private to fss-core;
/// its own copy of these assertions is the `versioned_replay_reaches_legacy_rules_only_for_v1_records`
/// unit test there.
#[test]
fn legacy_rules_are_reachable_only_through_versioned_v1_records() -> Result<(), Box<dyn Error>> {
    for (label, error_code) in [("none", None), ("empty", Some(String::new()))] {
        let records = legacy_records(error_code.clone())?;
        let public = EffectJournal::replay(records.clone());
        assert!(
            matches!(public, Err(ContractError::EvidenceRequired)),
            "{error_code:?}: {:?}",
            public.as_ref().err()
        );

        let v2_dir = ScratchDir::new(&format!("rules-v2-{label}"))?;
        let v2_path = v2_dir.journal_path();
        let as_v2_records: Vec<_> = records
            .iter()
            .cloned()
            .map(|record| (EFFECT_TRANSITION_V2_RECORD_KIND, record))
            .collect();
        write_kind_records(&v2_path, &as_v2_records)?;
        let as_v2 = DurableEffectJournal::open(&v2_path, IncompleteTailPolicy::Reject);
        assert!(
            matches!(
                as_v2,
                Err(DurableEffectError::Contract(
                    ContractError::EvidenceRequired
                ))
            ),
            "{error_code:?}: {:?}",
            as_v2.as_ref().err()
        );

        let v1_dir = ScratchDir::new(&format!("rules-v1-{label}"))?;
        let v1_path = v1_dir.journal_path();
        write_records(&v1_path, &records)?;
        let as_v1 = DurableEffectJournal::open(&v1_path, IncompleteTailPolicy::Reject)?;
        let legacy = as_v1
            .operation(&operation("legacy")?)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(legacy.record_version(), EffectRecordVersion::V1);
        assert_eq!(
            legacy.indeterminate_reason,
            Some(IndeterminateEffectReason::Unrecorded)
        );

        let backwards_dir = ScratchDir::new(&format!("rules-backwards-{label}"))?;
        let backwards_path = backwards_dir.journal_path();
        let mut backwards: Vec<_> = records
            .iter()
            .cloned()
            .map(|record| (EFFECT_TRANSITION_RECORD_KIND, record))
            .collect();
        if let Some(first) = backwards.first_mut() {
            first.0 = EFFECT_TRANSITION_V2_RECORD_KIND;
        }
        write_kind_records(&backwards_path, &backwards)?;
        let late_sequence = inspect(&backwards_path)?
            .records()
            .get(1)
            .map(JournalRecord::sequence)
            .ok_or(ContractError::NotFound)?;
        let backwards = DurableEffectJournal::open(&backwards_path, IncompleteTailPolicy::Reject);
        assert!(
            matches!(
                backwards,
                Err(DurableEffectError::UnexpectedRecordKind { sequence, kind })
                    if sequence == late_sequence && kind == EFFECT_TRANSITION_RECORD_KIND
            ),
            "{error_code:?}: {:?}",
            backwards.as_ref().err()
        );
    }
    Ok(())
}

/// fss-deir9 (D1/D3): the durable journal names the version of every record. A legacy operation
/// keeps the v1 receipt encoding after the upgrade, new records are v3 (fss-thzlz), the legacy
/// prefix is never rewritten, and a v1 record after a newer record is refused on open.
#[test]
fn durable_records_name_their_version_and_never_go_backwards() -> Result<(), Box<dyn Error>> {
    let dir = ScratchDir::new("versions")?;
    let path = dir.journal_path();
    write_records(&path, &legacy_records(None)?)?;
    let before = std::fs::read(&path)?;
    let legacy = operation("legacy")?;
    let fresh = operation("fresh")?;
    let proof = ContentDigest::sha256(b"versions-proof");
    let verified_digest = {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.transition(
            &legacy,
            EffectState::Observed,
            TimestampNs(40),
            Some(proof),
            None,
        )?;
        let verified = journal
            .reconcile_verified(&legacy, proof, TimestampNs(50))?
            .clone();
        assert_eq!(verified.record_version(), EffectRecordVersion::V1);
        assert_eq!(verified.digest_domain(), OperationReceipt::SCHEMA);
        assert_eq!(
            verified.indeterminate_reason,
            Some(IndeterminateEffectReason::Unrecorded)
        );
        let prepared = journal
            .prepare(
                intent("fresh")?,
                obligation("fresh")?,
                "delivery_proved",
                TimestampNs(60),
            )?
            .clone();
        assert_eq!(prepared.record_version(), EffectRecordVersion::V3);
        assert_eq!(prepared.digest_domain(), OperationReceipt::DIGEST_DOMAIN_V2);
        verified.receipt_digest()
    };
    let after = std::fs::read(&path)?;
    assert!(
        after.starts_with(&before),
        "the legacy records are never rewritten"
    );
    let kinds: Vec<u16> = inspect(&path)?
        .records()
        .iter()
        .map(JournalRecord::kind)
        .collect();
    let mut expected = vec![EFFECT_TRANSITION_RECORD_KIND; 4];
    expected.extend([EFFECT_TRANSITION_V3_RECORD_KIND; 3]);
    assert_eq!(kinds, expected);
    {
        let reopened = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let receipt = reopened.operation(&legacy).ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.receipt_digest(), verified_digest);
    }

    // A legacy record appended after a current one would reach the legacy rules: refused.
    {
        let mut raw = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        let late = EffectJournalTransition::Transition {
            operation_id: fresh,
            next: EffectState::Committed,
            now: TimestampNs(70),
            result_digest: None,
            error_code: None,
        };
        let _ = raw.append(EFFECT_TRANSITION_RECORD_KIND, &late.try_canonical_bytes()?)?;
    }
    let late_sequence = inspect(&path)?
        .records()
        .last()
        .map(JournalRecord::sequence)
        .ok_or(ContractError::NotFound)?;
    let refused = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject);
    assert!(
        matches!(
            refused,
            Err(DurableEffectError::UnexpectedRecordKind { sequence, kind })
                if sequence == late_sequence && kind == EFFECT_TRANSITION_RECORD_KIND
        ),
        "{:?}",
        refused.as_ref().err()
    );
    Ok(())
}

/// fss-deir9 (D1): the effect journal records of the review's h1 scenario exactly as pre-deir9
/// code (f2f6288) wrote them, as literal bytes (record kind 2): prepared at 10, committed at 20,
/// indeterminate at 30 (`provider_timeout`), observed at 40 with `sha256("h1-proof")`, reconciled
/// verified at 50. The bytes and the witnesses below come from an independent golden of f2f6288's
/// canonical encoding, not from this code; its digests equal the f2f6288-layout values the
/// fss-deir9 review measured (053ee4eb..., 2afcb543...).
const H1_V1_RECORDS: [&str; 5] = [
    "00000000000000186673732e6566666563745f7472616e736974696f6e2e76310100000000000000126f7065726174696f6e3a616c6572743a683100000000000000146964656d706f74656e63793a616c6572743a6831000000000000000e616c6572742e6469737061746368016905c59ff4a4442d05e17e0368c17c2434420541b0dd4b49111187aa35eb8ffd01014c15820976b18902bf16bec2c4b839c080e8e077ddd2ecafe67bdaf06b024500000000000000136f626c69676174696f6e3a616c6572743a6831000000000000000f64656c69766572795f70726f7665640000000000000000000000000000000a",
    "00000000000000186673732e6566666563745f7472616e736974696f6e2e76310200000000000000126f7065726174696f6e3a616c6572743a68310000000000000009636f6d6d6974746564000000000000000000000000000000140000",
    "00000000000000186673732e6566666563745f7472616e736974696f6e2e76310200000000000000126f7065726174696f6e3a616c6572743a6831000000000000000d696e64657465726d696e6174650000000000000000000000000000001e0001000000000000001070726f76696465725f74696d656f7574",
    "00000000000000186673732e6566666563745f7472616e736974696f6e2e76310200000000000000126f7065726174696f6e3a616c6572743a683100000000000000086f6273657276656400000000000000000000000000000028010134643fca71a81d5277669ea39c710b8ae5a00dffcbcb80309704beb3a57a451f00",
    "00000000000000186673732e6566666563745f7472616e736974696f6e2e76310300000000000000126f7065726174696f6e3a616c6572743a68310134643fca71a81d5277669ea39c710b8ae5a00dffcbcb80309704beb3a57a451f00000000000000000000000000000032",
];
/// The witness pre-deir9 code published for the h1 receipt after its indeterminate record.
const H1_V1_INDETERMINATE_WITNESS: &str =
    "sha256:053ee4eb52424a0833228c814bb649a82372141a2e4be217221e55d25d222f5f";
/// The witness pre-deir9 code published for the h1 receipt after its reconciliation.
const H1_V1_VERIFIED_WITNESS: &str =
    "sha256:2afcb54307d40b8f4ad900f1a4a14ef9fba122a02074eb4e135475c121d4a564";
/// Pre-deir9 digests of the legacy reason-less indeterminate receipt (absent, empty reason).
const LEGACY_V1_WITNESSES: [(Option<&str>, &str); 2] = [
    (
        None,
        "sha256:ef1b34511833abe850f247046f866a13a85cd45f60c016afd9c3810adbadb72f",
    ),
    (
        Some(""),
        "sha256:9cf8fc9d2b337c6d395eb89b75744e044d2bdf60746369dc1f48a597ce542bf5",
    ),
];

fn hex_bytes(hex: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| -> Result<u8, Box<dyn Error>> {
            Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?)
        })
        .collect()
}

/// Writes the first `count` h1 records exactly as pre-deir9 code did.
fn write_h1_v1_records(path: &Path, count: usize) -> Result<(), Box<dyn Error>> {
    let mut journal = Journal::open(path, IncompleteTailPolicy::Reject)?;
    for record in H1_V1_RECORDS.iter().take(count) {
        let _ = journal.append(EFFECT_TRANSITION_RECORD_KIND, &hex_bytes(record)?)?;
    }
    Ok(())
}

/// A ledger at `path` holding `witness` for the operation's outcome, as pre-deir9 code published it.
fn ledger_with_published_witness(
    path: &Path,
    receipt: &OperationReceipt,
    witness: ContentDigest,
) -> Result<DurableReferenceLedger, Box<dyn Error>> {
    let mut ledger =
        DurableReferenceLedger::open(path, "site:deir9-h1", IncompleteTailPolicy::Reject)?;
    let operation_id = receipt.intent.operation_id.clone();
    let outcome_root = ContentDigest::sha256(b"h1-published-outcome-root");
    let delta = EvidenceDelta {
        delta_id: format!("delta:alert-outcome:{}:1", operation_id.as_str()),
        family: ALERT_OUTCOME_FAMILY.to_owned(),
        object_id: ObjectId::parse(format!("object:effect:{}", operation_id.as_str()))?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(receipt.prepared_at, receipt.updated_at)?,
        plane: Plane::Effect,
        payload_digest: outcome_root,
        witness_digest: Some(witness),
        operation_id: Some(operation_id),
    };
    let batch = ledger.prepare_batch(
        BatchId::parse("batch:alert-outcome:h1:1")?,
        vec![delta],
        [outcome_root],
    )?;
    let _ = ledger.append(batch)?;
    Ok(ledger)
}

/// fss-deir9 (D1): a journal written by pre-deir9 code replays with its witness digests exactly
/// the values it published, so the published outcome is `Ledgered`, never a ledger conflict; the
/// journal file is never rewritten, and a legacy operation reconciled after the upgrade yields the
/// very witness pre-deir9 code computed for that reconciliation.
#[test]
fn pre_deir9_journal_replays_with_its_published_witnesses_and_no_ledger_conflict()
-> Result<(), Box<dyn Error>> {
    let h1 = operation("h1")?;
    for (label, count, state, witness) in [
        (
            "indeterminate",
            3,
            EffectState::Indeterminate,
            H1_V1_INDETERMINATE_WITNESS,
        ),
        ("verified", 5, EffectState::Verified, H1_V1_VERIFIED_WITNESS),
    ] {
        let dir = ScratchDir::new(&format!("h1-{label}"))?;
        let path = dir.journal_path();
        write_h1_v1_records(&path, count)?;
        let before = std::fs::read(&path)?;
        let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let receipt = journal
            .operation(&h1)
            .ok_or(ContractError::NotFound)?
            .clone();
        assert_eq!(receipt.state, state, "{label}");
        assert_eq!(receipt.record_version(), EffectRecordVersion::V1, "{label}");
        let witness = ContentDigest::parse(witness)?;
        assert_eq!(
            receipt.receipt_digest(),
            witness,
            "{label}: the pre-deir9 witness, exactly"
        );
        let ledger =
            ledger_with_published_witness(&dir.0.join("ledger.journal"), &receipt, witness)?;
        match journal.classify_obligation(&obligation("h1")?, &ledger)? {
            ObligationLedgerState::Ledgered(ledgered) => {
                assert_eq!(ledgered.receipt.receipt_digest(), witness, "{label}");
            }
            other => return Err(format!("{label}: expected Ledgered, got {other:?}").into()),
        }
        assert_eq!(
            std::fs::read(&path)?,
            before,
            "{label}: replay never rewrites the journal"
        );
    }

    let dir = ScratchDir::new("h1-upgraded")?;
    let path = dir.journal_path();
    write_h1_v1_records(&path, 3)?;
    let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let proof = ContentDigest::sha256(b"h1-proof");
    let _ = journal.transition(
        &h1,
        EffectState::Observed,
        TimestampNs(40),
        Some(proof),
        None,
    )?;
    let verified = journal
        .reconcile_verified(&h1, proof, TimestampNs(50))?
        .clone();
    assert_eq!(
        verified.receipt_digest(),
        ContentDigest::parse(H1_V1_VERIFIED_WITNESS)?
    );

    for (error_code, witness) in LEGACY_V1_WITNESSES {
        let label = error_code.map_or("none", |_| "empty");
        let dir = ScratchDir::new(&format!("legacy-witness-{label}"))?;
        let path = dir.journal_path();
        write_records(&path, &legacy_records(error_code.map(str::to_owned))?)?;
        let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let receipt = journal
            .operation(&operation("legacy")?)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(
            receipt.receipt_digest(),
            ContentDigest::parse(witness)?,
            "{label}"
        );
    }
    Ok(())
}

/// The receipt the effect journal builds for a fresh preparation with explicit authority (only
/// the effect journal builds a receipt; its encoding version is private, fss-deir9).
fn sample_operation_receipt() -> Result<OperationReceipt, Box<dyn Error>> {
    let intent = EffectIntent::new(
        OperationId::parse("op:alert:dispatch:01")?,
        IdempotencyKey::parse("idem:alert:2026-09-12:001")?,
        "alert.dispatch",
        ContentDigest::sha256(b"alert-request-body"),
        ContentDigest::sha256(b"precondition:event-corroborated"),
    )?;
    let authority =
        EffectAuthority::new("principal:operator:sec-ops", "cap:alert:dispatch", Some(42))?;
    let mut journal = EffectJournal::new();
    Ok(journal
        .prepare_with_authority(
            intent,
            ObligationId::parse("obligation:sample-receipt")?,
            "delivery_proved",
            authority,
            TimestampNs(1_700_000_000_000_000_000),
        )?
        .clone())
}

/// The canonical digest of `bytes` under `domain`, spelled out independently of the codec.
fn receipt_domain_digest(domain: &str, bytes: &[u8]) -> ContentDigest {
    let mut prefix = CanonicalEncoder::new();
    prefix.text("fss.canonical.v1");
    prefix.text(domain);
    let mut preimage = prefix.finish();
    preimage.extend_from_slice(bytes);
    ContentDigest::sha256(&preimage)
}

/// A v1 receipt of `receipt`'s intent (prepared at `receipt.prepared_at`, system authority), as
/// only the durable journal's sealed replay of a v1 record produces one: the record is written to a
/// real journal file as pre-deir9 code wrote it (kind 2) and the file is opened durably (fss-8dnfo).
fn replayed_v1_receipt(receipt: &OperationReceipt) -> Result<OperationReceipt, Box<dyn Error>> {
    let dir = ScratchDir::new("replayed-v1-receipt")?;
    let path = dir.journal_path();
    write_records(
        &path,
        &[EffectJournalTransition::Prepare {
            intent: receipt.intent.clone(),
            obligation_id: ObligationId::parse("obligation:replayed-v1")?,
            terminal_predicate: "delivery_proved".to_owned(),
            now: receipt.prepared_at,
        }],
    )?;
    let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    Ok(journal
        .operation(&receipt.intent.operation_id)
        .ok_or(ContractError::NotFound)?
        .clone())
}

/// The pre-deir9 canonical layout of a receipt with no commit time and no result digest.
fn v1_layout(receipt: &OperationReceipt) -> Vec<u8> {
    let mut legacy = CanonicalEncoder::new();
    receipt.intent.encode_canonical(&mut legacy);
    legacy.text(receipt.state.as_str());
    receipt.authority.encode_canonical(&mut legacy);
    receipt.prepared_at.encode_canonical(&mut legacy);
    legacy.bool(false);
    receipt.updated_at.encode_canonical(&mut legacy);
    legacy.bool(false);
    match &receipt.error_code {
        Some(code) => {
            legacy.bool(true);
            legacy.text(code);
        }
        None => legacy.bool(false),
    }
    legacy.finish()
}

/// fss-deir9 (D1): a v1 receipt keeps exactly its pre-deir9 canonical bytes and digest domain, and
/// its indeterminate reason is not in them; a v2 receipt opens with its own domain tag, its digest
/// binds the reason, and every shape round-trips. The public decoder refuses v1 bytes: a v1 receipt
/// exists only as the product of the durable journal's sealed replay (moved here from fss-core's
/// effect_schema_contract.rs by fss-8dnfo, its v1 receipt now read from a real durable file).
#[test]
fn operation_receipt_versions_keep_v1_bytes_and_bind_the_v2_reason() -> Result<(), Box<dyn Error>> {
    let base = sample_operation_receipt()?;
    // A fresh preparation is v3, which keeps the v2 bytes and digest domain (fss-thzlz).
    assert_eq!(base.record_version(), EffectRecordVersion::V3);
    assert_eq!(base.digest_domain(), OperationReceipt::DIGEST_DOMAIN_V2);
    let v1_base = replayed_v1_receipt(&base)?;
    assert_eq!(v1_base.record_version(), EffectRecordVersion::V1);
    assert_eq!(v1_base.digest_domain(), OperationReceipt::SCHEMA);
    let recorded = IndeterminateEffectReason::Recorded("provider_timeout".to_owned());
    let shapes = [
        (None, None),
        (Some("provider_timeout"), None),
        (None, Some(IndeterminateEffectReason::Unrecorded)),
        (Some("provider_timeout"), Some(recorded)),
    ];
    let mut v2_digests = BTreeSet::new();
    let mut v2_tag = CanonicalEncoder::new();
    v2_tag.u64(0);
    v2_tag.text(OperationReceipt::DIGEST_DOMAIN_V2);
    let v2_tag = v2_tag.finish();
    for (error_code, reason) in shapes {
        let mut receipt = base.clone();
        receipt.error_code = error_code.map(str::to_owned);
        receipt.indeterminate_reason = reason.clone();
        let mut encoder = CanonicalEncoder::new();
        receipt.encode_canonical(&mut encoder);
        let bytes = encoder.finish();
        assert!(
            bytes.starts_with(&v2_tag),
            "v2 opens with its tag: {error_code:?}"
        );
        let mut decoder = CanonicalDecoder::new(&bytes);
        let decoded = OperationReceipt::decode_canonical(&mut decoder)?;
        decoder.ensure_finished()?;
        assert_eq!(decoded, receipt, "v2 round trip of {error_code:?}");
        assert_eq!(
            receipt.receipt_digest(),
            receipt_domain_digest(OperationReceipt::DIGEST_DOMAIN_V2, &bytes)
        );
        assert!(
            v2_digests.insert(receipt.receipt_digest()),
            "the v2 digest binds the reason: {error_code:?}"
        );

        // v1: exactly the layout before the reason existed; the reason is not in its bytes.
        let mut v1 = v1_base.clone();
        v1.error_code = error_code.map(str::to_owned);
        let mut without_reason = CanonicalEncoder::new();
        v1.encode_canonical(&mut without_reason);
        let without_reason = without_reason.finish();
        v1.indeterminate_reason = reason;
        let mut with_reason = CanonicalEncoder::new();
        v1.encode_canonical(&mut with_reason);
        let legacy = with_reason.finish();
        assert_eq!(legacy, v1_layout(&v1), "v1 bytes of {error_code:?}");
        assert_eq!(
            legacy, without_reason,
            "a v1 receipt's reason is not digest-bound"
        );
        assert_eq!(
            v1.receipt_digest(),
            receipt_domain_digest(OperationReceipt::SCHEMA, &legacy)
        );
        let refused = OperationReceipt::decode_canonical(&mut CanonicalDecoder::new(&legacy));
        assert!(
            matches!(refused, Err(ContractError::LegacyReceiptRequiresJournal)),
            "{error_code:?}: {refused:?}"
        );
    }
    assert_eq!(v2_digests.len(), 4);

    // An unknown v2 reason tag is refused, never read as some reason.
    let mut encoder = CanonicalEncoder::new();
    base.encode_canonical(&mut encoder);
    let mut bytes = encoder.finish();
    let last = bytes.len().checked_sub(1).ok_or("empty receipt bytes")?;
    assert_eq!(bytes.get(last), Some(&0));
    if let Some(tag) = bytes.get_mut(last) {
        *tag = 3;
    }
    let refused = OperationReceipt::decode_canonical(&mut CanonicalDecoder::new(&bytes));
    assert!(
        matches!(refused, Err(ContractError::InvalidIdentifier)),
        "{refused:?}"
    );

    // An operation id spelled like the v2 tag is a valid id; its v1 bytes are still v1, refused.
    let mut lookalike = base.clone();
    lookalike.intent.operation_id = OperationId::parse(OperationReceipt::DIGEST_DOMAIN_V2)?;
    let refused =
        OperationReceipt::decode_canonical(&mut CanonicalDecoder::new(&v1_layout(&lookalike)));
    assert!(
        matches!(refused, Err(ContractError::LegacyReceiptRequiresJournal)),
        "{refused:?}"
    );
    Ok(())
}

// fss-thzlz: the durable journal writes v3 (kind 4) records, under which a cancellation must be a
// proof-bound `Cancel` record. A journal written between fss-deir9 and fss-thzlz (kind 3) still
// opens with the unbound cancellation digests it holds.

/// Appends `records`, each under its own record kind, exactly as a journal would hold them.
fn write_kinded(
    path: &Path,
    records: &[(u16, EffectJournalTransition)],
) -> Result<(), Box<dyn Error>> {
    let mut journal = Journal::open(path, IncompleteTailPolicy::Reject)?;
    for (kind, record) in records {
        let _ = journal.append(*kind, &record.try_canonical_bytes()?)?;
    }
    Ok(())
}

fn prepare_record(name: &str, now: i128) -> Result<EffectJournalTransition, Box<dyn Error>> {
    Ok(EffectJournalTransition::Prepare {
        intent: intent(name)?,
        obligation_id: obligation(name)?,
        terminal_predicate: "delivery_proved".to_owned(),
        now: TimestampNs(now),
    })
}

/// The cancellation proof of the operation `prepare_record(name, now)` prepares, for `evidence`.
fn bound_proof(
    name: &str,
    now: i128,
    evidence: ContentDigest,
) -> Result<ContentDigest, Box<dyn Error>> {
    Ok(EffectCancellationRecord::for_prepared(
        &PreparedEffect {
            intent: intent(name)?,
            obligation_id: obligation(name)?,
            terminal_predicate: "delivery_proved".to_owned(),
            prepared_at: TimestampNs(now),
        },
        evidence,
    )
    .proof_digest())
}

/// The cancellation as the alert dispatch wrote it before fss-thzlz: an unbound digest.
fn unbound_cancel(
    name: &str,
    now: i128,
    digest: ContentDigest,
) -> Result<EffectJournalTransition, Box<dyn Error>> {
    Ok(EffectJournalTransition::Transition {
        operation_id: operation(name)?,
        next: EffectState::Cancelled,
        now: TimestampNs(now),
        result_digest: Some(digest),
        error_code: Some("stale_event_authority".to_owned()),
    })
}

fn bound_cancel(
    name: &str,
    now: i128,
    evidence: ContentDigest,
    proof_digest: ContentDigest,
) -> Result<EffectJournalTransition, Box<dyn Error>> {
    Ok(EffectJournalTransition::Cancel {
        operation_id: operation(name)?,
        now: TimestampNs(now),
        cancel_request_evidence: evidence,
        proof_digest,
        reason: None,
    })
}

#[test]
fn unbound_v2_cancellation_replays_and_opens() -> Result<(), Box<dyn Error>> {
    let dir = ScratchDir::new("thzlz-v2-cancel")?;
    let path = dir.journal_path();
    let unbound = ContentDigest::sha256(b"alert-cancel-proof-as-dispatch-wrote-it");
    write_kinded(
        &path,
        &[
            (
                EFFECT_TRANSITION_V2_RECORD_KIND,
                prepare_record("bystander", 5)?,
            ),
            (
                EFFECT_TRANSITION_V2_RECORD_KIND,
                prepare_record("legacy", 10)?,
            ),
            (
                EFFECT_TRANSITION_V2_RECORD_KIND,
                unbound_cancel("legacy", 20, unbound)?,
            ),
        ],
    )?;
    let before = std::fs::read(&path)?;
    let legacy = operation("legacy")?;
    let bystander = operation("bystander")?;
    let evidence = ContentDigest::sha256(b"bystander-cancel-request-evidence");
    let root = {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let receipt = journal.operation(&legacy).ok_or(ContractError::NotFound)?;
        assert_eq!(receipt.state, EffectState::Cancelled);
        assert_eq!(receipt.record_version(), EffectRecordVersion::V2);
        assert_eq!(receipt.result_digest, Some(unbound));
        assert_eq!(receipt.error_code.as_deref(), Some("stale_event_authority"));
        let held = journal
            .obligation(&obligation("legacy")?)
            .ok_or(ContractError::NotFound)?;
        assert_eq!(held.state, ObligationState::Cancelled);
        assert_eq!(held.proof_digest, Some(unbound));
        assert_eq!(
            journal
                .effect_journal()
                .cancellation_record_version(&legacy),
            Some(EffectRecordVersion::V2)
        );

        // A new cancellation of the v2 bystander is written as a bound v3 record.
        let cancelled = journal
            .cancel(&bystander, TimestampNs(30), evidence, None)?
            .clone();
        assert_eq!(cancelled.record_version(), EffectRecordVersion::V2);
        assert_eq!(
            cancelled.result_digest,
            Some(bound_proof("bystander", 5, evidence)?)
        );
        // Prepared by a v2 record, cancelled today: the cancellation is a v3 record.
        assert_eq!(
            journal
                .effect_journal()
                .cancellation_record_version(&bystander),
            Some(EffectRecordVersion::V3)
        );
        journal.last_root()
    };
    assert!(std::fs::read(&path)?.starts_with(&before));
    let kinds: Vec<u16> = inspect(&path)?
        .records()
        .iter()
        .map(JournalRecord::kind)
        .collect();
    assert_eq!(
        kinds,
        vec![
            EFFECT_TRANSITION_V2_RECORD_KIND,
            EFFECT_TRANSITION_V2_RECORD_KIND,
            EFFECT_TRANSITION_V2_RECORD_KIND,
            EFFECT_TRANSITION_V3_RECORD_KIND,
        ]
    );
    let reopened = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.last_root(), root);
    assert_eq!(
        reopened
            .operation(&legacy)
            .and_then(|receipt| receipt.result_digest),
        Some(unbound)
    );
    Ok(())
}

#[test]
fn v3_cancellation_must_be_proof_bound_to_open() -> Result<(), Box<dyn Error>> {
    let evidence = ContentDigest::sha256(b"cancel-request-evidence");
    let honest = bound_proof("legacy", 10, evidence)?;
    let v2 = EFFECT_TRANSITION_V2_RECORD_KIND;
    let v3 = EFFECT_TRANSITION_V3_RECORD_KIND;
    let cases = [
        (
            "unbound v3 cancellation",
            vec![
                (v3, prepare_record("legacy", 10)?),
                (v3, unbound_cancel("legacy", 20, honest)?),
            ],
            ContractError::EvidenceRequired,
        ),
        (
            "forged v3 cancellation proof",
            vec![
                (v3, prepare_record("legacy", 10)?),
                (
                    v3,
                    bound_cancel(
                        "legacy",
                        20,
                        evidence,
                        ContentDigest::sha256(b"forged-cancellation-proof"),
                    )?,
                ),
            ],
            ContractError::InvalidDigest,
        ),
        (
            "v2 operation, forged v3 cancellation proof",
            vec![
                (v2, prepare_record("legacy", 10)?),
                (
                    v3,
                    bound_cancel(
                        "legacy",
                        20,
                        evidence,
                        ContentDigest::sha256(b"forged-cancellation-proof"),
                    )?,
                ),
            ],
            ContractError::InvalidDigest,
        ),
        (
            "bound cancellation in a v2 record",
            vec![
                (v2, prepare_record("legacy", 10)?),
                (v2, bound_cancel("legacy", 20, evidence, honest)?),
            ],
            ContractError::InvalidEffectTransition,
        ),
    ];
    for (label, records, refusal) in cases {
        let dir = ScratchDir::new(&format!("thzlz-{}", label.replace([' ', ','], "-")))?;
        let path = dir.journal_path();
        write_kinded(&path, &records)?;
        let opened = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject);
        assert!(
            matches!(&opened, Err(DurableEffectError::Contract(error)) if *error == refusal),
            "{label}: {:?}",
            opened.as_ref().err()
        );
    }

    // A v2 record after a v3 record is refused on open.
    let dir = ScratchDir::new("thzlz-backwards")?;
    let path = dir.journal_path();
    write_kinded(
        &path,
        &[
            (v3, prepare_record("legacy", 10)?),
            (v2, unbound_cancel("legacy", 20, honest)?),
        ],
    )?;
    let late_sequence = inspect(&path)?
        .records()
        .last()
        .map(JournalRecord::sequence)
        .ok_or(ContractError::NotFound)?;
    let refused = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject);
    assert!(
        matches!(
            refused,
            Err(DurableEffectError::UnexpectedRecordKind { sequence, kind })
                if sequence == late_sequence && kind == v2
        ),
        "{:?}",
        refused.as_ref().err()
    );

    // The honest bound v3 cancellation opens.
    let dir = ScratchDir::new("thzlz-bound")?;
    let path = dir.journal_path();
    write_kinded(
        &path,
        &[
            (v3, prepare_record("legacy", 10)?),
            (v3, bound_cancel("legacy", 20, evidence, honest)?),
        ],
    )?;
    let journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    let receipt = journal
        .operation(&operation("legacy")?)
        .ok_or(ContractError::NotFound)?;
    assert_eq!(receipt.state, EffectState::Cancelled);
    assert_eq!(receipt.record_version(), EffectRecordVersion::V3);
    assert_eq!(receipt.result_digest, Some(honest));
    Ok(())
}

#[test]
fn durable_cancel_writes_one_bound_record_and_refuses_before_writing() -> Result<(), Box<dyn Error>>
{
    let dir = ScratchDir::new("thzlz-durable-cancel")?;
    let path = dir.journal_path();
    let legacy = operation("legacy")?;
    let evidence = ContentDigest::sha256(b"cancel-request-evidence");
    let (cancelled, root) = {
        let mut journal = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.prepare(
            intent("legacy")?,
            obligation("legacy")?,
            "delivery_proved",
            TimestampNs(10),
        )?;
        let before = std::fs::metadata(&path)?.len();
        let honest = journal
            .effect_journal()
            .cancellation_proof(&legacy, evidence)?;
        let unbound = journal.transition(
            &legacy,
            EffectState::Cancelled,
            TimestampNs(20),
            Some(honest),
            Some("stale_event_authority".to_owned()),
        );
        assert!(
            matches!(
                unbound,
                Err(DurableEffectError::Contract(
                    ContractError::EvidenceRequired
                ))
            ),
            "{unbound:?}"
        );
        let empty_reason = journal.cancel(&legacy, TimestampNs(20), evidence, Some(String::new()));
        assert!(
            matches!(
                empty_reason,
                Err(DurableEffectError::Contract(
                    ContractError::EvidenceRequired
                ))
            ),
            "{empty_reason:?}"
        );
        assert_eq!(
            std::fs::metadata(&path)?.len(),
            before,
            "a refused cancellation writes no record"
        );
        let cancelled = journal
            .cancel(
                &legacy,
                TimestampNs(20),
                evidence,
                Some("stale_event_authority".to_owned()),
            )?
            .clone();
        assert_eq!(cancelled.result_digest, Some(honest));
        assert_eq!(honest, bound_proof("legacy", 10, evidence)?);
        (cancelled, journal.last_root())
    };
    let report = inspect(&path)?;
    let records = report.records();
    let kinds: Vec<u16> = records.iter().map(JournalRecord::kind).collect();
    assert_eq!(kinds, vec![EFFECT_TRANSITION_V3_RECORD_KIND; 2]);
    let last = records.last().ok_or(ContractError::NotFound)?;
    assert_eq!(
        EffectJournalTransition::from_canonical_bytes(last.payload())?,
        EffectJournalTransition::Cancel {
            operation_id: legacy.clone(),
            now: TimestampNs(20),
            cancel_request_evidence: evidence,
            proof_digest: bound_proof("legacy", 10, evidence)?,
            reason: Some("stale_event_authority".to_owned()),
        }
    );
    let reopened = DurableEffectJournal::open(&path, IncompleteTailPolicy::Reject)?;
    assert_eq!(reopened.operation(&legacy), Some(&cancelled));
    assert_eq!(reopened.last_root(), root);
    Ok(())
}
