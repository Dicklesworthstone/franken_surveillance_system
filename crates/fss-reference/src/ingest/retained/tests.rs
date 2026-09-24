#![forbid(unsafe_code)]
use super::*;
use fss_core::CanonicalEncoder;

fn fixture() -> Result<FileImportManifest, FileIngestError> {
    let capsule = CapsuleId::parse("capsule:retained:0")?;
    Ok(FileImportManifest {
        input_sha256: ContentDigest::sha256(b"abcdabcdxy"),
        input_bytes: 10,
        format: "mjpeg".to_owned(),
        detector_evidence: "fixture".to_owned(),
        chunk_bytes: 4,
        ordered_chunks: vec![
            ContentDigest::sha256(b"abcd"),
            ContentDigest::sha256(b"abcd"),
            ContentDigest::sha256(b"xy"),
        ],
        segment_spans: vec![SegmentSpan {
            segment_index: 0,
            offset: 2,
            len: 7,
            segment_sha256: ContentDigest::sha256(b"cdabcdx"),
            capsule_id: capsule.clone(),
            gap_before: true,
        }],
        omission_spans: vec![FileOmissionSpan {
            offset: 0,
            len: 2,
            reason: "prefix".to_owned(),
        }],
        capsule_ids: vec![capsule],
        limits_digest: ContentDigest::sha256(b"limits"),
        adapter_id: ADP_FILE_ROW_ID.to_owned(),
        adapter_generation: ADP_FILE_GENERATION.to_owned(),
        part_roots: vec![],
        capture_time_label: "unknown".to_owned(),
    })
}

fn read(d: ContentDigest) -> Result<Vec<u8>, FileIngestError> {
    if d == ContentDigest::sha256(b"abcd") {
        Ok(b"abcd".to_vec())
    } else if d == ContentDigest::sha256(b"xy") {
        Ok(b"xy".to_vec())
    } else {
        Err(invalid("unknown test chunk"))
    }
}

#[test]
fn manifest_roundtrips_without_new_storage_dialect() -> Result<(), FileIngestError> {
    let m = fixture()?;
    assert_eq!(
        FileImportManifest::from_retained_bytes(
            &m.canonical_bytes(),
            m.canonical_digest(),
            RetainedReadLimits::default()
        )?,
        m
    );
    Ok(())
}

#[test]
fn every_truncation_and_trailing_bytes_are_refused() -> Result<(), FileIngestError> {
    let mut bytes = fixture()?.canonical_bytes();
    for end in 0..bytes.len() {
        let prefix = &bytes[..end];
        assert!(
            FileImportManifest::from_retained_bytes(
                prefix,
                ContentDigest::sha256(prefix),
                RetainedReadLimits::default()
            )
            .is_err()
        );
    }
    bytes.push(0);
    assert!(
        FileImportManifest::from_retained_bytes(
            &bytes,
            ContentDigest::sha256(&bytes),
            RetainedReadLimits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn authority_digest_mismatch_is_refused() -> Result<(), FileIngestError> {
    let m = fixture()?;
    assert!(
        FileImportManifest::from_retained_bytes(
            &m.canonical_bytes(),
            ContentDigest::sha256(b"other"),
            RetainedReadLimits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn huge_count_is_rejected_before_allocation() {
    let mut e = CanonicalEncoder::new();
    e.text("fss.canonical.v1");
    e.text(FILE_IMPORT_MANIFEST_SCHEMA);
    e.digest(ContentDigest::sha256(b"source"));
    e.u64(10);
    e.text("mjpeg");
    e.text("fixture");
    e.u64(4);
    e.u64(u64::MAX);
    let bytes = e.finish();
    assert!(
        FileImportManifest::from_retained_bytes(
            &bytes,
            ContentDigest::sha256(&bytes),
            RetainedReadLimits::default()
        )
        .is_err()
    );
}

#[test]
fn zero_overflow_and_rebound_ranges_are_refused() -> Result<(), FileIngestError> {
    for case in 0..7 {
        let mut m = fixture()?;
        match case {
            0 => m.chunk_bytes = 0,
            1 => m.segment_spans[0].len = 0,
            2 => m.segment_spans[0].offset = u64::MAX,
            3 => m.segment_spans[0].segment_index = 1,
            4 => m.segment_spans[0].gap_before = false,
            5 => m.capsule_ids.clear(),
            _ => m.ordered_chunks.truncate(2),
        }
        assert!(m.validate_retained(RetainedReadLimits::default()).is_err());
    }
    Ok(())
}

#[test]
fn cross_chunk_segment_and_repeated_chunks_preserve_source_order() -> Result<(), FileIngestError> {
    let m = fixture()?;
    assert_eq!(
        assemble_segment(&m, 0, RetainedReadLimits::default(), read)?,
        b"cdabcdx"
    );
    assert_eq!(verify_source_chunks(&m, read)?, m.input_sha256);
    Ok(())
}

#[test]
fn allocation_budget_is_checked_before_source_io() -> Result<(), FileIngestError> {
    let m = fixture()?;
    let mut reads = 0;
    let limits = RetainedReadLimits {
        max_segment_bytes: 6,
        ..RetainedReadLimits::default()
    };
    assert!(
        assemble_segment(&m, 0, limits, |d| {
            reads += 1;
            read(d)
        })
        .is_err()
    );
    assert_eq!(reads, 0);
    Ok(())
}

#[test]
fn corrupt_short_and_oversized_chunks_are_refused() -> Result<(), FileIngestError> {
    let m = fixture()?;
    for replacement in [b"z".as_slice(), b"zz".as_slice(), b"xyz".as_slice()] {
        assert!(
            verify_source_chunks(&m, |d| {
                if d == ContentDigest::sha256(b"xy") {
                    Ok(replacement.to_vec())
                } else {
                    read(d)
                }
            })
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn independent_source_and_segment_digests_are_enforced() -> Result<(), FileIngestError> {
    let mut m = fixture()?;
    m.input_sha256 = ContentDigest::sha256(b"different source");
    assert!(verify_source_chunks(&m, read).is_err());
    m.segment_spans[0].segment_sha256 = ContentDigest::sha256(b"different segment");
    assert!(assemble_segment(&m, 0, RetainedReadLimits::default(), read).is_err());
    Ok(())
}

#[test]
fn partitioned_and_unknown_capture_classifications_are_not_silently_accepted()
-> Result<(), FileIngestError> {
    let mut m = fixture()?;
    m.part_roots.push(ContentDigest::sha256(b"unresolved part"));
    assert!(m.validate_retained(RetainedReadLimits::default()).is_err());
    m.part_roots.clear();
    m.capture_time_label = "trusted_hardware".to_owned();
    assert!(m.validate_retained(RetainedReadLimits::default()).is_err());
    Ok(())
}
