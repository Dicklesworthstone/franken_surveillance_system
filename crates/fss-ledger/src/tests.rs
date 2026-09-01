use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, EvidenceDelta, ObjectId, Plane, ReferenceLedger,
    TimestampNs, sha256,
};

use crate::batch_codec::{BatchCodecError, decode_batch, encode_batch};
use crate::durable::DurableReferenceLedger;
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
    let payload_len = payload.len() as u32;
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

fn sample_batch() -> Result<fss_core::EvidenceDeltaBatch, Box<dyn Error>> {
    let ledger = ReferenceLedger::new("test-site");
    let delta = EvidenceDelta {
        delta_id: "delta:1".to_owned(),
        family: "sensor_capsule".to_owned(),
        object_id: ObjectId::parse("object:camera:1")?,
        prior_generation: None,
        new_generation: 1,
        validity: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        plane: Plane::Authority,
        payload_digest: ContentDigest::sha256(b"payload"),
        witness_digest: Some(ContentDigest::sha256(b"witness")),
        operation_id: None,
    };
    Ok(ledger.prepare_batch(
        BatchId::parse("batch:1")?,
        vec![delta],
        [ContentDigest::sha256(b"child")],
    )?)
}

#[test]
fn committed_records_replay_exactly() -> Result<(), Box<dyn Error>> {
    let (first, first_root) = encoded_record(1, 7, b"alpha", [0; 32]);
    let (second, second_root) = encoded_record(2, 9, b"beta", first_root);
    let mut bytes = first;
    bytes.extend_from_slice(&second);
    let report = recover_bytes(&bytes)?;
    assert_eq!(report.records().len(), 2);
    assert_eq!(report.records()[0].payload(), b"alpha");
    assert_eq!(report.records()[1].payload(), b"beta");
    assert_eq!(report.last_root().bytes(), second_root);
    Ok(())
}

#[test]
fn every_torn_second_record_suffix_is_uncommitted() -> Result<(), Box<dyn Error>> {
    let (first, first_root) = encoded_record(1, 1, b"first", [0; 32]);
    let (second, _) = encoded_record(2, 2, b"second-record", first_root);
    let committed_first = first.len();
    let mut bytes = first;
    bytes.extend_from_slice(&second);
    for cut in committed_first + 1..bytes.len() {
        let report = recover_bytes(&bytes[..cut])?;
        assert_eq!(report.records().len(), 1);
        assert_eq!(report.committed_len() as usize, committed_first);
        assert_eq!(report.incomplete_tail(), Some(committed_first as u64));
    }
    Ok(())
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
fn batch_codec_round_trips_canonical_state() -> Result<(), Box<dyn Error>> {
    let batch = sample_batch()?;
    let encoded = encode_batch(&batch)?;
    assert_eq!(decode_batch(&encoded)?, batch);

    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        decode_batch(&trailing),
        Err(BatchCodecError::TrailingBytes)
    ));
    Ok(())
}

#[test]
fn file_append_reopen_and_explicit_tail_repair() -> Result<(), Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "fss-ledger-{}-{}.journal",
        std::process::id(),
        sha256(b"file_append_reopen_and_explicit_tail_repair")[0]
    ));
    let _ = fs::remove_file(&path);
    {
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        let first = journal.append(11, b"one")?;
        let second = journal.append(12, b"two")?;
        assert_ne!(first.root(), second.root());
        assert_eq!(journal.verify()?.records().len(), 2);
    }
    {
        let mut raw = OpenOptions::new().append(true).open(&path)?;
        raw.write_all(b"torn")?;
        raw.sync_all()?;
    }
    let inspected = inspect(&path)?;
    assert_eq!(inspected.records().len(), 2);
    assert!(inspected.incomplete_tail().is_some());
    assert!(matches!(
        Journal::open(&path, IncompleteTailPolicy::Reject),
        Err(JournalError::IncompleteTail { .. })
    ));
    let mut repaired = Journal::open(&path, IncompleteTailPolicy::Truncate)?;
    let third = repaired.append(13, b"three")?;
    assert_eq!(third.sequence(), 3);
    assert_eq!(repaired.verify()?.records().len(), 3);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn durable_reference_ledger_restarts_to_identical_anchor() -> Result<(), Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "fss-durable-ledger-{}-{}.journal",
        std::process::id(),
        sha256(b"durable_reference_ledger_restarts_to_identical_anchor")[0]
    ));
    let _ = fs::remove_file(&path);

    let expected_anchor;
    let expected_journal_root;
    {
        let mut durable =
            DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Reject)?;
        let batch = durable.prepare_batch(
            BatchId::parse("batch:durable:1")?,
            vec![EvidenceDelta {
                delta_id: "delta:durable:1".to_owned(),
                family: "coverage".to_owned(),
                object_id: ObjectId::parse("object:coverage:1")?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(100), TimestampNs(120))?,
                plane: Plane::Authority,
                payload_digest: ContentDigest::sha256(b"coverage-payload"),
                witness_digest: Some(ContentDigest::sha256(b"coverage-witness")),
                operation_id: None,
            }],
            [ContentDigest::sha256(b"coverage-child")],
        )?;
        durable.append(batch)?;
        expected_anchor = durable.current().anchor.clone();
        expected_journal_root = durable.verify_storage()?;
    }

    {
        let mut reopened =
            DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Reject)?;
        assert_eq!(reopened.current().anchor, expected_anchor);
        assert_eq!(reopened.journal_root(), expected_journal_root);
        assert_eq!(reopened.batches().len(), 1);
        assert_eq!(reopened.verify_storage()?, expected_journal_root);
    }

    let _ = fs::remove_file(path);
    Ok(())
}
