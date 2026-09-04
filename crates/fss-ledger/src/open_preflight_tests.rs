use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;

use fss_core::{
    BatchId, CaptureInterval, ContentDigest, ContractError, EvidenceDelta, ObjectId, Plane,
    TimestampNs,
};

use crate::{
    BatchCodecError, DurableLedgerError, DurableReferenceLedger, IncompleteTailPolicy, Journal,
    inspect,
};

fn temp_journal(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("fss-ledger-{}-{name}.journal", std::process::id()))
}

fn append_torn_suffix(path: &std::path::Path) -> Result<u64, Box<dyn Error>> {
    let mut raw = OpenOptions::new().append(true).open(path)?;
    raw.write_all(b"torn-tail")?;
    raw.sync_all()?;
    Ok(fs::metadata(path)?.len())
}

#[test]
fn semantic_failure_precedes_requested_tail_truncation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("semantic-preflight");
    let _ = fs::remove_file(&path);
    {
        let mut journal = Journal::open(&path, IncompleteTailPolicy::Reject)?;
        let _ = journal.append(1, b"not-a-canonical-batch")?;
    }
    let before = append_torn_suffix(&path)?;

    assert!(matches!(
        DurableReferenceLedger::open(&path, "test-site", IncompleteTailPolicy::Truncate),
        Err(DurableLedgerError::Codec(BatchCodecError::InvalidMagic))
    ));
    assert_eq!(fs::metadata(&path)?.len(), before);
    assert!(inspect(&path)?.incomplete_tail().is_some());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn lineage_failure_precedes_requested_tail_truncation() -> Result<(), Box<dyn Error>> {
    let path = temp_journal("lineage-preflight");
    let _ = fs::remove_file(&path);
    {
        let mut durable =
            DurableReferenceLedger::open(&path, "site:a", IncompleteTailPolicy::Reject)?;
        let batch = durable.prepare_batch(
            BatchId::parse("batch:lineage:1")?,
            vec![EvidenceDelta {
                delta_id: "delta:lineage:1".to_owned(),
                family: "source".to_owned(),
                object_id: ObjectId::parse("object:source:1")?,
                prior_generation: None,
                new_generation: 1,
                validity: CaptureInterval::new(TimestampNs(1), TimestampNs(2))?,
                plane: Plane::Authority,
                payload_digest: ContentDigest::sha256(b"payload"),
                witness_digest: None,
                operation_id: None,
            }],
            [],
        )?;
        let _ = durable.append(batch)?;
    }
    let before = append_torn_suffix(&path)?;

    assert!(matches!(
        DurableReferenceLedger::open(&path, "site:b", IncompleteTailPolicy::Truncate),
        Err(DurableLedgerError::Contract(ContractError::StaleAnchor))
    ));
    assert_eq!(fs::metadata(&path)?.len(), before);
    assert!(inspect(&path)?.incomplete_tail().is_some());

    let _ = fs::remove_file(path);
    Ok(())
}
