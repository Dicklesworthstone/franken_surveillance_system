#![forbid(unsafe_code)]
//! Every accepted transfer journal prefix must fit the cold recovery format.

use fss_core::{ContentDigest, TimestampNs};
use fss_object::atp_lifecycle::{
    AtpLifecycleError, LifecycleEvent, MAX_FAILURE_DOMAINS, MAX_JOURNAL_FILE_BYTES, MAX_LABEL_BYTES,
    TransferId, TransferJournal,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn domain_lists_must_be_replayable_before_admission() -> TestResult {
    let id = TransferId::from_digest(ContentDigest::sha256(b"transfer"));
    let mut journal = TransferJournal::new(id, 10)?;
    let accepted = journal.append(
        1,
        TimestampNs(0),
        LifecycleEvent::SatisfyDurability {
            failure_domains: vec!["x".repeat(MAX_LABEL_BYTES); MAX_FAILURE_DOMAINS],
        },
        0,
        0,
    )?;
    for invalid in [
        vec!["x".to_owned(); MAX_FAILURE_DOMAINS + 1],
        vec!["x".repeat(MAX_LABEL_BYTES + 1)],
    ] {
        for event in [
            LifecycleEvent::SatisfyDurability { failure_domains: invalid.clone() },
            LifecycleEvent::QualifyReplicas { failure_domains: invalid.clone() },
        ] {
            assert!(matches!(
                journal.append(1, TimestampNs(1), event, 0, 0),
                Err(AtpLifecycleError::JournalBoundsExceeded { .. })
            ));
        }
    }
    let bytes = journal.export_framed_prefix(10)?;
    assert_eq!(TransferJournal::decode_framed_records(id, &bytes, 10)?, vec![accepted]);
    Ok(())
}

#[test]
fn journal_byte_budget_includes_framing_and_preserves_the_last_good_head() -> TestResult {
    let digest = ContentDigest::sha256(b"child");
    let id = TransferId::from_digest(digest);
    let mut journal = TransferJournal::new(id, 512)?;
    let event = LifecycleEvent::Quarantine {
        reason: "quarantine".to_owned(),
        affected_children: vec![digest; 1900],
    };
    let mut total = 0;
    for seq in 0..512 {
        let head = journal.head_digest();
        match journal.append(1, TimestampNs(seq), event.clone(), 0, 0) {
            Ok(record) => total += 4 + record.to_canonical_bytes()?.len(),
            Err(AtpLifecycleError::JournalBoundsExceeded { .. }) => {
                assert_eq!(journal.head_digest(), head);
                assert_eq!(journal.records().len(), seq as usize);
                let last = journal.records().last().ok_or("expected a nonempty journal")?;
                let next_len = 4 + last.to_canonical_bytes()?.len();
                assert!(total as u64 <= MAX_JOURNAL_FILE_BYTES);
                assert!((total + next_len) as u64 > MAX_JOURNAL_FILE_BYTES);
                let bytes = journal.export_framed_prefix(journal.records().len())?;
                assert_eq!(bytes.len(), total);
                assert_eq!(TransferJournal::decode_framed_records(id, &bytes, 512)?, journal.records());
                let oversized = vec![0; MAX_JOURNAL_FILE_BYTES as usize + 1];
                assert!(matches!(
                    TransferJournal::decode_framed_records(id, &oversized, 512),
                    Err(AtpLifecycleError::JournalBoundsExceeded { .. })
                ));
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err("record budget reached before byte budget".into())
}
