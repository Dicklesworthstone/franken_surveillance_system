use std::fs;
use std::fs::OpenOptions;
use std::io::Write;

use fss_core::sha256;

use crate::error::{CorruptionKind, JournalError};
use crate::format::{COMMIT_MAGIC, FORMAT_VERSION, HEADER_LEN, RECORD_MAGIC, record_root};
use crate::journal::{IncompleteTailPolicy, Journal};
use crate::recovery::{inspect, recover_bytes};

fn encoded_record(
    sequence: u64,
    kind: u16,
    payload: &[u8],
    previous_root: [u8; 32],
) -> (Vec<u8>, [u8; 32]) {
    let payload_len = u32::try_from(payload.len()).unwrap_or(0);
    let payload_digest = sha256(payload);
    let root = record_root(sequence, kind, payload_len, previous_root, payload_digest);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&RECORD_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(&previous_root);
    bytes.extend_from_slice(&payload_digest);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&COMMIT_MAGIC);
    bytes.extend_from_slice(&root);
    (bytes, root)
}

#[test]
fn committed_records_replay_exactly() {
    let (first, first_root) = encoded_record(1, 7, b"alpha", [0; 32]);
    let (second, second_root) = encoded_record(2, 9, b"beta", first_root);
    let mut bytes = first;
    bytes.extend_from_slice(&second);
    let report = recover_bytes(&bytes).unwrap_or_else(|_| unreachable!());
    assert_eq!(report.records().len(), 2);
    assert_eq!(report.records()[0].payload(), b"alpha");
    assert_eq!(report.records()[1].payload(), b"beta");
    assert_eq!(report.last_root().bytes(), second_root);
}

#[test]
fn every_torn_second_record_suffix_is_uncommitted() {
    let (first, first_root) = encoded_record(1, 1, b"first", [0; 32]);
    let (second, _) = encoded_record(2, 2, b"second-record", first_root);
    let committed_first = first.len();
    let mut bytes = first;
    bytes.extend_from_slice(&second);
    for cut in committed_first + 1..bytes.len() {
        let report = recover_bytes(&bytes[..cut]).unwrap_or_else(|_| unreachable!());
        assert_eq!(report.records().len(), 1);
        assert_eq!(report.committed_len() as usize, committed_first);
        assert_eq!(report.incomplete_tail(), Some(committed_first as u64));
    }
}

#[test]
fn payload_and_commit_mutation_are_corruption() {
    let (mut payload_bytes, _) = encoded_record(1, 1, b"payload", [0; 32]);
    payload_bytes[HEADER_LEN] ^= 1;
    assert!(matches!(
        recover_bytes(&payload_bytes),
        Err(JournalError::Corrupt {
            kind: CorruptionKind::PayloadDigest,
            ..
        })
    ));

    let (mut root_bytes, _) = encoded_record(1, 1, b"payload", [0; 32]);
    let last = root_bytes.len() - 1;
    root_bytes[last] ^= 1;
    assert!(matches!(
        recover_bytes(&root_bytes),
        Err(JournalError::Corrupt {
            kind: CorruptionKind::CommitRoot,
            ..
        })
    ));
}

#[test]
fn file_append_reopen_and_explicit_tail_repair() {
    let path = std::env::temp_dir().join(format!(
        "fss-ledger-{}-{}.journal",
        std::process::id(),
        sha256(b"file_append_reopen_and_explicit_tail_repair")[0]
    ));
    let _ = fs::remove_file(&path);
    {
        let mut journal =
            Journal::open(&path, IncompleteTailPolicy::Reject).unwrap_or_else(|_| unreachable!());
        let first = journal.append(11, b"one").unwrap_or_else(|_| unreachable!());
        let second = journal.append(12, b"two").unwrap_or_else(|_| unreachable!());
        assert_ne!(first.root(), second.root());
        assert_eq!(
            journal
                .verify()
                .unwrap_or_else(|_| unreachable!())
                .records()
                .len(),
            2
        );
    }
    {
        let mut raw = OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap_or_else(|_| unreachable!());
        raw.write_all(b"torn").unwrap_or_else(|_| unreachable!());
        raw.sync_all().unwrap_or_else(|_| unreachable!());
    }
    let inspected = inspect(&path).unwrap_or_else(|_| unreachable!());
    assert_eq!(inspected.records().len(), 2);
    assert!(inspected.incomplete_tail().is_some());
    assert!(matches!(
        Journal::open(&path, IncompleteTailPolicy::Reject),
        Err(JournalError::IncompleteTail { .. })
    ));
    let mut repaired =
        Journal::open(&path, IncompleteTailPolicy::Truncate).unwrap_or_else(|_| unreachable!());
    let third = repaired
        .append(13, b"three")
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(third.sequence(), 3);
    assert_eq!(
        repaired
            .verify()
            .unwrap_or_else(|_| unreachable!())
            .records()
            .len(),
        3
    );
    let _ = fs::remove_file(path);
}
